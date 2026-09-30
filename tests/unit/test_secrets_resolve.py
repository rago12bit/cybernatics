"""core.secrets.resolve.resolve_secret (Week 47 task 4, plan §22.2, ADR-0033). The real OpenBao
round-trip (a secret written to KV, then read back through Settings/LLMConfig) is live-verified
against a real container; see docs/v2-week47-verification.md. Unit tests here mock OpenBaoClient
itself to cover the "off means off" fallback logic without needing a running instance."""

from __future__ import annotations

import pytest

from core.secrets.openbao import OpenBaoError
from core.secrets.resolve import resolve_secret


def test_falls_back_to_env_var_when_openbao_is_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BULWARK_OPENBAO_ADDR", raising=False)
    monkeypatch.delenv("BULWARK_OPENBAO_TOKEN", raising=False)
    monkeypatch.setenv("MY_SECRET", "from-env")
    assert resolve_secret("MY_SECRET", kv_path="x/y") == "from-env"


def test_prefers_openbaos_value_when_configured_and_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BULWARK_OPENBAO_ADDR", "http://openbao:8200")
    monkeypatch.setenv("BULWARK_OPENBAO_TOKEN", "t")
    monkeypatch.setenv("MY_SECRET", "stale-env-value")
    monkeypatch.setattr(
        "core.secrets.resolve.OpenBaoClient.get_secret",
        lambda self, path, key="value": "from-openbao",
    )
    assert resolve_secret("MY_SECRET", kv_path="x/y") == "from-openbao"


def test_falls_back_to_env_var_when_openbao_has_no_such_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BULWARK_OPENBAO_ADDR", "http://openbao:8200")
    monkeypatch.setenv("BULWARK_OPENBAO_TOKEN", "t")
    monkeypatch.setenv("MY_SECRET", "from-env")
    monkeypatch.setattr(
        "core.secrets.resolve.OpenBaoClient.get_secret", lambda self, path, key="value": None
    )
    assert resolve_secret("MY_SECRET", kv_path="x/y") == "from-env"


def test_falls_back_to_env_var_when_openbao_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BULWARK_OPENBAO_ADDR", "http://openbao:8200")
    monkeypatch.setenv("BULWARK_OPENBAO_TOKEN", "t")
    monkeypatch.setenv("MY_SECRET", "from-env")

    def _raise(self: object, path: str, key: str = "value") -> str | None:
        raise OpenBaoError("connection refused")

    monkeypatch.setattr("core.secrets.resolve.OpenBaoClient.get_secret", _raise)
    assert resolve_secret("MY_SECRET", kv_path="x/y") == "from-env"


def test_missing_env_var_and_unconfigured_openbao_returns_empty_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BULWARK_OPENBAO_ADDR", raising=False)
    monkeypatch.delenv("BULWARK_OPENBAO_TOKEN", raising=False)
    monkeypatch.delenv("MY_SECRET", raising=False)
    assert resolve_secret("MY_SECRET", kv_path="x/y") == ""
