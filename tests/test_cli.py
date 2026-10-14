"""The console script, driven through a monkeypatched ``urllib.request.urlopen``.

This is the one place the stdlib transport is exercised, so the patch here
replaces the autouse refusal with a fake that answers from ``FakeRekor``.
"""
from __future__ import annotations

import io
import urllib.error
import urllib.request

import pytest

from aileron_anchor.cli import main

from conftest import extend_journal


class _Response(io.BytesIO):
    def __init__(self, status, headers, body):
        super().__init__(body)
        self.status = status
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class _Headers(dict):
    def items(self):
        return dict.items(self)


def route_urlopen(rekor):
    def fake_urlopen(req, timeout=None):
        assert timeout is not None, "the transport must always set a timeout"
        body = req.data
        status, headers, data = rekor.transport(
            req.get_method(), req.full_url, body, dict(req.header_items()))
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "err", _Headers(headers),
                                         io.BytesIO(data))
        return _Response(status, _Headers(headers), data)
    return fake_urlopen


@pytest.fixture
def wired(monkeypatch, rekor):
    monkeypatch.setattr(urllib.request, "urlopen", route_urlopen(rekor))
    return rekor


def test_cli_push_then_check(journal, wired, capsys):
    log_path, key_path, pub_path = journal
    code = main(["push", log_path, "--key", pub_path, "--rekor-url", wired.base_url])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "OK: anchor recorded" in out
    assert "Rekor accepted entry" in out

    code = main(["check", log_path, "--key", pub_path, "--rekor-url", wired.base_url])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "OK: every anchor verified" in out
    assert "trust on first use" in out


def test_cli_check_reports_truncation_with_exit_2(journal, wired, capsys, tmp_path):
    log_path, key_path, pub_path = journal
    extend_journal(log_path, 2)
    from aileron.signing import sign_checkpoint
    sign_checkpoint(log_path, key_path)
    assert main(["push", log_path, "--key", pub_path, "--rekor-url", wired.base_url]) == 0
    lines = open(log_path, encoding="utf-8").read().splitlines()
    open(log_path, "w", encoding="utf-8").write("\n".join(lines[:2]) + "\n")
    capsys.readouterr()
    code = main(["check", log_path, "--key", pub_path, "--rekor-url", wired.base_url])
    out = capsys.readouterr().out
    assert code == 2
    assert "TRUNCATED" in out and out.rstrip().endswith("(see PROBLEM lines)")


def test_cli_http_error_exits_1(journal, wired, capsys):
    log_path, _key, pub_path = journal
    wired.force_status = 500
    code = main(["push", log_path, "--key", pub_path, "--rekor-url", wired.base_url])
    out = capsys.readouterr().out
    assert code == 1
    assert "NOT VERIFIED" in out and "HTTP 500" in out


def test_cli_rekor_pubkey_file(journal, wired, capsys, tmp_path):
    log_path, _key, pub_path = journal
    pem = tmp_path / "rekor.pub"
    pem.write_bytes(wired.public_pem)
    code = main(["push", log_path, "--key", pub_path, "--rekor-url", wired.base_url,
                 "--rekor-pubkey", str(pem)])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "supplied out of band" in out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_cli_default_rekor_url_is_public_instance():
    from aileron_anchor.cli import build_parser
    args = build_parser().parse_args(["check", "x.jsonl"])
    assert args.rekor_url == "https://rekor.sigstore.dev"
