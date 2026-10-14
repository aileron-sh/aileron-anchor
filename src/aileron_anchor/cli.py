"""Command line entry point: ``aileron-anchor push`` and ``aileron-anchor check``."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .anchors import check, push
from .rekor import DEFAULT_REKOR_URL, RekorClient, urllib_transport


def _read_pem(path: str | None) -> bytes | None:
    if path is None:
        return None
    with open(path, "rb") as fh:
        return fh.read()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aileron-anchor",
        description="Anchor Aileron checkpoints in Sigstore Rekor and check the journal "
                    "against them.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("log", help="path to the Aileron journal (<name>.chain.jsonl)")
        p.add_argument("--key", help="Ed25519 public key PEM (default: the path the "
                                     "checkpoint names)")
        p.add_argument("--rekor-url", default=DEFAULT_REKOR_URL,
                       help=f"Rekor instance (default: {DEFAULT_REKOR_URL})")
        p.add_argument("--rekor-pubkey", metavar="PEM",
                       help="Rekor's public key, obtained out of band (default: fetched "
                            "from the instance, trust on first use)")
        p.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds")

    p_push = sub.add_parser("push", help="anchor a checkpoint in Rekor")
    common(p_push)
    p_push.add_argument("--index", type=int,
                        help="checkpoint index to anchor (default: the newest)")

    p_check = sub.add_parser("check", help="verify anchors against Rekor and the local files")
    common(p_check)
    p_check.add_argument("--no-discover", action="store_true",
                         help="do not ask Rekor's search index for entries under this key "
                              "that the anchors file does not list")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    client = RekorClient(args.rekor_url, transport=urllib_transport(args.timeout))
    try:
        rekor_pem = _read_pem(args.rekor_pubkey)
    except OSError as exc:
        print(f"ERROR: {exc}")
        return 1
    if args.command == "push":
        report = push(args.log, args.key, client, index=args.index, rekor_key_pem=rekor_pem)
    else:
        report = check(args.log, args.key, client, rekor_key_pem=rekor_pem,
                       discover=not args.no_discover)
    for line in report.lines:
        print(line)
    if report.exit_code == 0:
        print("OK: " + ("anchor recorded" if args.command == "push"
                        else "every anchor verified and the local files agree with Rekor"))
    elif report.exit_code == 2:
        print("TAMPERED: the local files disagree with what Rekor holds (see PROBLEM lines)")
    else:
        print("NOT VERIFIED: could not complete (see ERROR lines)")
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
