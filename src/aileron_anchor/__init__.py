"""aileron-anchor: anchor Aileron checkpoints in Sigstore Rekor.

Aileron itself makes no network calls. This package is the piece that does:
it uploads signed checkpoints to a public append-only transparency log and
later checks the local journal against what the log holds, so that deleting
the newest checkpoints or truncating the journal tail is detectable from a
place the attacker does not control.
"""
from __future__ import annotations

from .anchors import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_TAMPERED,
    AnchorError,
    Report,
    anchors_path,
    check,
    push,
    read_anchors,
)
from .rekor import (
    DEFAULT_REKOR_URL,
    LogEntry,
    RekorClient,
    RekorError,
    RekorVerificationError,
    build_rekord_entry,
    verify_inclusion,
    verify_set,
)

__version__ = "0.1.0"

__all__ = [
    "AnchorError",
    "DEFAULT_REKOR_URL",
    "EXIT_ERROR",
    "EXIT_OK",
    "EXIT_TAMPERED",
    "LogEntry",
    "RekorClient",
    "RekorError",
    "RekorVerificationError",
    "Report",
    "__version__",
    "anchors_path",
    "build_rekord_entry",
    "check",
    "push",
    "read_anchors",
    "verify_inclusion",
    "verify_set",
]
