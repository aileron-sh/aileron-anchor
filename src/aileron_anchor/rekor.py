"""Rekor client, entry construction, and verification of what Rekor returns.

Everything that touches the network lives here, behind one injectable
``transport`` callable, so the rest of the package and the whole test suite
never open a socket.

The entry type is ``rekord`` with the artifact inlined. Aileron checkpoints are
signed with pure Ed25519, which signs the whole message rather than a digest.
Rekor's ``hashedrekord`` type verifies Ed25519 keys in the prehashed
``Ed25519ph`` mode (SHA-512 over the message), so a pure Ed25519 signature
would be rejected there. ``rekord`` verifies the signature over the inlined
``data.content`` bytes with the plain Ed25519 verifier, which is what we need.
The payload is a few hundred bytes, so inlining costs nothing.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
USER_AGENT = "aileron-anchor/0.1.0"

# (method, url, body or None, headers) -> (status, lowercase headers, body bytes)
Transport = Callable[[str, str, "bytes | None", dict], "tuple[int, dict, bytes]"]


class RekorError(Exception):
    """A request to Rekor failed or returned something we refuse to use."""


class RekorVerificationError(RekorError):
    """Rekor's response did not verify (bad SET, bad proof, bad shape)."""


def urllib_transport(timeout: float = 30.0) -> Transport:
    """The default transport: stdlib ``urllib.request`` with a timeout.

    HTTP error statuses are returned as ordinary responses rather than raised,
    so the caller decides what each status means. Transport-level failures
    (DNS, refused connection, TLS) raise ``RekorError``.
    """

    def send(method: str, url: str, body: bytes | None, headers: dict) -> tuple[int, dict, bytes]:
        req = urllib.request.Request(url, data=body, method=method)
        for name, value in headers.items():
            req.add_header(name, value)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
        except urllib.error.HTTPError as exc:
            data = exc.read() if hasattr(exc, "read") else b""
            return exc.code, {k.lower(): v for k, v in exc.headers.items()}, data
        except (urllib.error.URLError, OSError) as exc:
            raise RekorError(f"{method} {url} failed: {exc}") from exc

    return send


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: Any, what: str) -> bytes:
    if not isinstance(text, str):
        raise RekorVerificationError(f"{what} is not a string")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RekorVerificationError(f"{what} is not valid base64: {exc}") from exc


def build_rekord_entry(payload: bytes, signature: bytes, public_key_pem: bytes) -> dict:
    """The proposed ``rekord`` entry for one Aileron checkpoint.

    ``payload`` is the exact bytes the checkpoint signature covers,
    ``signature`` the raw Ed25519 signature, and ``public_key_pem`` the
    SubjectPublicKeyInfo PEM. Rekor's ``x509`` signature format accepts a bare
    PEM public key as well as a certificate.
    """
    return {
        "apiVersion": "0.0.1",
        "kind": "rekord",
        "spec": {
            "data": {"content": b64(payload)},
            "signature": {
                "format": "x509",
                "content": b64(signature),
                "publicKey": {"content": b64(public_key_pem)},
            },
        },
    }


@dataclass
class LogEntry:
    """One Rekor log entry as returned by the API, decoded but not yet trusted."""

    uuid: str
    body_b64: str
    body: dict
    log_index: int
    integrated_time: int
    log_id: str
    signed_entry_timestamp: str | None
    inclusion_proof: dict | None
    raw: dict = field(repr=False)

    @property
    def body_bytes(self) -> bytes:
        return base64.b64decode(self.body_b64)


def parse_log_entry(obj: Any) -> LogEntry:
    """Decode the ``{uuid: {...}}`` map Rekor returns into a ``LogEntry``.

    Every field is type-checked here so later code can rely on the shapes.
    Anything unexpected raises ``RekorVerificationError``.
    """
    if not isinstance(obj, dict) or len(obj) != 1:
        raise RekorVerificationError("expected a map with exactly one entry UUID")
    (uuid, entry), = obj.items()
    if not isinstance(uuid, str) or not isinstance(entry, dict):
        raise RekorVerificationError("malformed log entry map")
    body_b64 = entry.get("body")
    body_bytes = unb64(body_b64, "entry body")
    try:
        body = json.loads(body_bytes)
    except ValueError as exc:
        raise RekorVerificationError(f"entry body is not JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise RekorVerificationError("entry body is not a JSON object")
    log_index = entry.get("logIndex")
    integrated_time = entry.get("integratedTime")
    log_id = entry.get("logID")
    for name, value in (("logIndex", log_index), ("integratedTime", integrated_time)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise RekorVerificationError(f"entry {name} is not a non-negative integer")
    if not isinstance(log_id, str):
        raise RekorVerificationError("entry logID is not a string")
    verification = entry.get("verification") or {}
    if not isinstance(verification, dict):
        raise RekorVerificationError("entry verification is not an object")
    set_b64 = verification.get("signedEntryTimestamp")
    if set_b64 is not None and not isinstance(set_b64, str):
        raise RekorVerificationError("signedEntryTimestamp is not a string")
    proof = verification.get("inclusionProof")
    if proof is not None and not isinstance(proof, dict):
        raise RekorVerificationError("inclusionProof is not an object")
    return LogEntry(
        uuid=uuid,
        body_b64=body_b64,
        body=body,
        log_index=log_index,
        integrated_time=integrated_time,
        log_id=log_id,
        signed_entry_timestamp=set_b64,
        inclusion_proof=proof,
        raw=entry,
    )


class RekorClient:
    """Thin client for the handful of Rekor endpoints anchoring needs."""

    def __init__(self, base_url: str = DEFAULT_REKOR_URL, transport: Transport | None = None):
        self.base_url = base_url.rstrip("/")
        self._send = transport or urllib_transport()

    def _request(self, method: str, path: str, body: dict | None = None,
                 accept: str = "application/json") -> tuple[int, dict, bytes]:
        headers = {"Accept": accept, "User-Agent": USER_AGENT}
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        return self._send(method, f"{self.base_url}{path}", data, headers)

    @staticmethod
    def _json(data: bytes, what: str) -> Any:
        try:
            return json.loads(data)
        except ValueError as exc:
            raise RekorError(f"{what}: response is not JSON") from exc

    def create_entry(self, proposed: dict) -> LogEntry:
        """Upload a proposed entry. Returns the stored entry.

        A 409 means Rekor already holds this exact entry; the existing entry is
        fetched and returned so that re-running ``push`` is harmless. Any other
        non-201 status is an error: nothing is recorded locally unless Rekor
        confirmed the entry.
        """
        status, headers, data = self._request("POST", "/api/v1/log/entries", proposed)
        if status == 201:
            return parse_log_entry(self._json(data, "create entry"))
        if status == 409:
            location = headers.get("location", "")
            uuid = location.rstrip("/").rsplit("/", 1)[-1]
            if not _looks_like_uuid(uuid):
                raise RekorError("Rekor reported a conflict but gave no usable entry location")
            return self.get_entry(uuid)
        raise RekorError(f"create entry: HTTP {status}: {data[:300].decode('utf-8', 'replace')}")

    def get_entry(self, uuid: str) -> LogEntry:
        """Fetch one entry by UUID, with its inclusion proof and SET."""
        if not _looks_like_uuid(uuid):
            raise RekorError(f"refusing to fetch malformed entry UUID {uuid!r}")
        status, _headers, data = self._request("GET", f"/api/v1/log/entries/{uuid}")
        if status == 404:
            raise RekorError(f"Rekor has no entry {uuid}")
        if status != 200:
            raise RekorError(f"get entry {uuid}: HTTP {status}")
        entry = parse_log_entry(self._json(data, "get entry"))
        if entry.uuid != uuid:
            raise RekorVerificationError(
                f"asked Rekor for entry {uuid} but it answered with {entry.uuid}")
        return entry

    def search_by_public_key(self, public_key_pem: bytes) -> list[str]:
        """UUIDs of every entry signed by ``public_key_pem``, via the search index.

        The search index is a convenience feature of Rekor v1 and may be absent
        on some deployments; callers decide how to treat a failure.
        """
        query = {"publicKey": {"format": "x509", "content": b64(public_key_pem)}}
        status, _headers, data = self._request("POST", "/api/v1/index/retrieve", query)
        if status != 200:
            raise RekorError(f"search index: HTTP {status}")
        result = self._json(data, "search index")
        if not isinstance(result, list) or not all(isinstance(u, str) for u in result):
            raise RekorError("search index: response is not a list of UUIDs")
        return result

    def public_key_pem(self) -> bytes:
        """The PEM public key Rekor says it signs with.

        Trusting this is trust on first use against the same server that
        produced the entries. Pass a copy obtained out of band wherever the
        answer matters.
        """
        status, _headers, data = self._request(
            "GET", "/api/v1/log/publicKey", accept="application/x-pem-file")
        if status != 200:
            raise RekorError(f"get public key: HTTP {status}")
        if b"-----BEGIN PUBLIC KEY-----" not in data:
            raise RekorError("get public key: response is not a PEM public key")
        return data


def _looks_like_uuid(text: str) -> bool:
    if len(text) not in (64, 80):
        return False
    try:
        bytes.fromhex(text)
    except ValueError:
        return False
    return True


# --- Verifying what Rekor returned --------------------------------------------


def load_rekor_public_key(pem: bytes):
    """Load Rekor's signing key; ECDSA and Ed25519 are the forms Rekor deploys."""
    try:
        key = serialization.load_pem_public_key(pem)
    except ValueError as exc:
        raise RekorVerificationError(f"Rekor public key is not a PEM public key: {exc}") from exc
    if not isinstance(key, (ec.EllipticCurvePublicKey, Ed25519PublicKey)):
        raise RekorVerificationError(
            f"unsupported Rekor key type {type(key).__name__}; expected ECDSA or Ed25519")
    return key


def rekor_key_der(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def rekor_log_id(key) -> str:
    """Rekor's logID is the hex SHA-256 of the DER SubjectPublicKeyInfo."""
    return hashlib.sha256(rekor_key_der(key)).hexdigest()


def _verify_with_rekor_key(key, signature: bytes, message: bytes, what: str) -> None:
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(signature, message)
    except InvalidSignature as exc:
        raise RekorVerificationError(f"{what}: signature does not verify") from exc
    except ValueError as exc:
        raise RekorVerificationError(f"{what}: malformed signature: {exc}") from exc


def jcs(obj: Any) -> bytes:
    """RFC 8785 canonical JSON for the flat ASCII objects Rekor signs.

    The SET payload holds two integers and two ASCII strings, so the general
    rules of JCS (UTF-16 key ordering, ES6 number formatting) collapse to
    sorted keys, no whitespace, and no ASCII escaping. Anything outside that
    subset (floats, non-ASCII text, nested containers) is refused rather than
    canonicalized wrong.
    """

    def check(value: Any) -> None:
        if isinstance(value, bool) or value is None:
            return
        if isinstance(value, int):
            return
        if isinstance(value, str):
            if not value.isascii():
                raise RekorVerificationError("jcs: non-ASCII string not supported")
            return
        if isinstance(value, dict):
            for k, v in value.items():
                if not isinstance(k, str) or not k.isascii():
                    raise RekorVerificationError("jcs: non-ASCII key not supported")
                check(v)
            return
        if isinstance(value, list):
            for v in value:
                check(v)
            return
        raise RekorVerificationError(f"jcs: unsupported value type {type(value).__name__}")

    check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_set(entry: LogEntry, rekor_key) -> None:
    """Verify the Signed Entry Timestamp with Rekor's key.

    The SET is Rekor's signature over the canonical JSON of ``{body,
    integratedTime, logID, logIndex}``. A valid SET means Rekor itself vouches
    that this body was integrated at this index and time. We also require the
    entry's ``logID`` to be the fingerprint of the key we verified with, so a
    SET from some other log cannot be passed off as this one's.
    """
    if entry.signed_entry_timestamp is None:
        raise RekorVerificationError("entry carries no signedEntryTimestamp")
    expected_log_id = rekor_log_id(rekor_key)
    if entry.log_id != expected_log_id:
        raise RekorVerificationError(
            f"entry logID {entry.log_id} is not the fingerprint of the Rekor key "
            f"({expected_log_id})")
    payload = jcs({
        "body": entry.body_b64,
        "integratedTime": entry.integrated_time,
        "logID": entry.log_id,
        "logIndex": entry.log_index,
    })
    signature = unb64(entry.signed_entry_timestamp, "signedEntryTimestamp")
    _verify_with_rekor_key(rekor_key, signature, payload, "SET")


def leaf_hash(body_bytes: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256 over 0x00 followed by the leaf bytes."""
    return hashlib.sha256(b"\x00" + body_bytes).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion_path(index: int, tree_size: int, leaf: bytes, path: list[bytes],
                          root: bytes) -> None:
    """RFC 9162 section 2.1.3.2 inclusion proof check."""
    if index < 0 or tree_size <= 0 or index >= tree_size:
        raise RekorVerificationError("inclusion proof: index outside the tree")
    fn, sn, r = index, tree_size - 1, leaf
    for p in path:
        if sn == 0:
            raise RekorVerificationError("inclusion proof: too many hashes for the tree size")
        if fn & 1 or fn == sn:
            r = _node_hash(p, r)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise RekorVerificationError("inclusion proof: too few hashes for the tree size")
    if r != root:
        raise RekorVerificationError("inclusion proof: computed root does not match")


# The signed-note format marks each signature line with U+2014. Spelled as an
# escape so no literal em dash appears in this codebase.
EM_DASH = "\u2014"


@dataclass
class SignedNote:
    origin: str
    tree_size: int
    root_hash: bytes
    text: bytes
    signatures: list[tuple[str, bytes]]


def parse_signed_note(note: str) -> SignedNote:
    """Parse a transparency-dev signed note (Rekor's checkpoint format).

    The note text ends at the last blank line, keeping its final newline;
    every line after it is ``<em dash> <name> <base64 of 4-byte key hint plus
    signature>``.
    """
    data = note.encode("utf-8")
    split = data.rfind(b"\n\n")
    if split < 0:
        raise RekorVerificationError("checkpoint note has no signature section")
    text = data[:split + 1]
    lines = text.decode("utf-8").split("\n")
    if len(lines) < 4:  # origin, size, root, trailing empty string from the final newline
        raise RekorVerificationError("checkpoint note is too short")
    origin = lines[0]
    try:
        tree_size = int(lines[1])
    except ValueError as exc:
        raise RekorVerificationError("checkpoint note tree size is not an integer") from exc
    root_hash = unb64(lines[2], "checkpoint root hash")
    if len(root_hash) != 32:
        raise RekorVerificationError("checkpoint root hash is not 32 bytes")
    signatures: list[tuple[str, bytes]] = []
    for line in data[split + 2:].decode("utf-8").split("\n"):
        if not line:
            continue
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != EM_DASH:
            raise RekorVerificationError(f"malformed checkpoint signature line {line!r}")
        sig = unb64(parts[2], "checkpoint signature")
        if len(sig) < 5:
            raise RekorVerificationError("checkpoint signature is too short")
        signatures.append((parts[1], sig))
    if not signatures:
        raise RekorVerificationError("checkpoint note carries no signatures")
    return SignedNote(origin, tree_size, root_hash, text, signatures)


def verify_signed_note(note: SignedNote, rekor_key) -> None:
    """Require one signature line whose key hint matches ``rekor_key`` and whose
    signature verifies over the note text."""
    hint = hashlib.sha256(rekor_key_der(rekor_key)).digest()[:4]
    candidates = [sig[4:] for _name, sig in note.signatures if sig[:4] == hint]
    if not candidates:
        raise RekorVerificationError("checkpoint note has no signature by the Rekor key")
    last_error: RekorVerificationError | None = None
    for sig in candidates:
        try:
            _verify_with_rekor_key(rekor_key, sig, note.text, "checkpoint")
            return
        except RekorVerificationError as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


def verify_inclusion(entry: LogEntry, rekor_key=None) -> None:
    """Verify the entry's inclusion proof against its checkpoint.

    Checks that the entry UUID ends in the leaf hash of the body, that the
    proof hashes lead from that leaf to the proof's root, and that the root and
    tree size agree with the signed checkpoint. With ``rekor_key`` the
    checkpoint's signature is verified too; without it the proof only shows
    internal consistency of the response.
    """
    proof = entry.inclusion_proof
    if proof is None:
        raise RekorVerificationError("entry carries no inclusionProof")
    leaf = leaf_hash(entry.body_bytes)
    if entry.uuid[-64:] != leaf.hex():
        raise RekorVerificationError("entry UUID does not end in the leaf hash of its body")
    index = proof.get("logIndex")
    tree_size = proof.get("treeSize")
    for name, value in (("logIndex", index), ("treeSize", tree_size)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise RekorVerificationError(f"inclusion proof {name} is not an integer")
    hashes_hex = proof.get("hashes")
    if not isinstance(hashes_hex, list) or not all(isinstance(h, str) for h in hashes_hex):
        raise RekorVerificationError("inclusion proof hashes are not a list of strings")
    try:
        path = [bytes.fromhex(h) for h in hashes_hex]
        root = bytes.fromhex(proof.get("rootHash", ""))
    except ValueError as exc:
        raise RekorVerificationError(f"inclusion proof hash is not hex: {exc}") from exc
    if len(root) != 32 or any(len(h) != 32 for h in path):
        raise RekorVerificationError("inclusion proof hashes are not 32 bytes")
    verify_inclusion_path(index, tree_size, leaf, path, root)
    checkpoint = proof.get("checkpoint")
    if not isinstance(checkpoint, str):
        raise RekorVerificationError("inclusion proof carries no checkpoint")
    note = parse_signed_note(checkpoint)
    if note.root_hash != root or note.tree_size != tree_size:
        raise RekorVerificationError("inclusion proof root or size disagrees with the checkpoint")
    if rekor_key is not None:
        verify_signed_note(note, rekor_key)
