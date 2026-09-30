"""`bulwark secrets migrate-env` (Week 47 task 4, plan §22.2, ADR-0033). The real OpenBao round-trip
is live-verified against a real container; see docs/v2-week47-verification.md. This covers the
command's own logic (which env vars it reads, migrated/skipped reporting, the missing-config guard)
with OpenBaoClient mocked."""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()


def test_requires_openbao_addr_and_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BULWARK_OPENBAO_ADDR", raising=False)
    monkeypatch.delenv("BULWARK_OPENBAO_TOKEN", raising=False)
    r = runner.invoke(app, ["secrets", "migrate-env"])
    assert r.exit_code == 1
    assert "BULWARK_OPENBAO_ADDR" in r.output


def test_migrates_every_set_secret_and_reports_the_skipped_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BULWARK_OPENBAO_ADDR", "http://openbao:8200")
    monkeypatch.setenv("BULWARK_OPENBAO_TOKEN", "t")
    monkeypatch.setenv("BULWARK_API_TOKEN", "real-token")
    monkeypatch.setenv("BULWARK_GITHUB_WEBHOOK_SECRET", "real-webhook")
    monkeypatch.delenv("BULWARK_GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("BULWARK_LLM_API_KEY", raising=False)

    written: dict[str, str] = {}
    monkeypatch.setattr(
        "core.secrets.openbao.OpenBaoClient.ensure_kv_engine_enabled", lambda self: None
    )
    monkeypatch.setattr(
        "core.secrets.openbao.OpenBaoClient.put_secret",
        lambda self, path, value, key="value": written.__setitem__(path, value),
    )

    r = runner.invoke(app, ["secrets", "migrate-env"])
    assert r.exit_code == 0, r.output
    assert written == {
        "bulwark/api-token": "real-token",
        "bulwark/github-webhook-secret": "real-webhook",
    }
    assert "BULWARK_API_TOKEN" in r.output and "BULWARK_GITHUB_WEBHOOK_SECRET" in r.output
    assert "BULWARK_GITHUB_APP_PRIVATE_KEY" in r.output  # reported as skipped
    assert "BULWARK_LLM_API_KEY" in r.output  # reported as skipped


def test_a_write_failure_exits_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    from core.secrets.openbao import OpenBaoError

    monkeypatch.setenv("BULWARK_OPENBAO_ADDR", "http://openbao:8200")
    monkeypatch.setenv("BULWARK_OPENBAO_TOKEN", "t")
    monkeypatch.setenv("BULWARK_API_TOKEN", "real-token")

    def _raise(self: Any, path: str, value: str, key: str = "value") -> None:
        raise OpenBaoError("write failed")

    monkeypatch.setattr(
        "core.secrets.openbao.OpenBaoClient.ensure_kv_engine_enabled", lambda self: None
    )
    monkeypatch.setattr("core.secrets.openbao.OpenBaoClient.put_secret", _raise)

    r = runner.invoke(app, ["secrets", "migrate-env"])
    assert r.exit_code == 1
    assert "write failed" in r.output
