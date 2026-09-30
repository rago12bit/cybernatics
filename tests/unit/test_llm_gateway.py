"""Model gateway routing, the local Ollama backend, the path denylist, and PII redaction (plan §21.1)."""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from core.llm.client import Completion, LLMConfig
from core.llm.gateway import (
    Backend,
    GatewayConfig,
    PrivacyModeViolation,
    Task,
    gateway_status,
    make_gateway_client,
)
from core.llm.ollama_client import DEFAULT_BASE_URL, OllamaClient, OllamaConfig, make_ollama_client
from core.llm.pathguard import DEFAULT_DENYLIST, denylist_from_env, is_denylisted
from core.llm.pii import redact_pii

# ---- gateway routing -----------------------------------------------------------------------------


def test_default_backend_is_hosted_and_routes_to_the_configured_anthropic_client() -> None:
    cfg = GatewayConfig(default_backend=Backend.HOSTED, privacy_mode=False)
    hosted = LLMConfig(enabled=True, api_key="k")
    client = make_gateway_client(Task.FIX, gateway_cfg=cfg, hosted_cfg=hosted)
    assert client is not None and client.model == hosted.model


def test_local_backend_is_used_when_selected_and_configured() -> None:
    cfg = GatewayConfig(default_backend=Backend.LOCAL)
    local = OllamaConfig(enabled=True, model="llama3.1")
    client = make_gateway_client(Task.FIX, gateway_cfg=cfg, local_cfg=local)
    assert isinstance(client, OllamaClient) and client.model == "llama3.1"


def test_per_task_override_env_var_beats_the_gateway_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BULWARK_LLM_ROUTE_FIX", "local")
    cfg = GatewayConfig(default_backend=Backend.HOSTED)
    local = OllamaConfig(enabled=True)
    client = make_gateway_client(Task.FIX, gateway_cfg=cfg, local_cfg=local)
    assert isinstance(client, OllamaClient)


def test_privacy_mode_forces_local_even_when_the_default_backend_is_hosted() -> None:
    cfg = GatewayConfig(default_backend=Backend.HOSTED, privacy_mode=True)
    local = OllamaConfig(enabled=True)
    hosted = LLMConfig(enabled=True, api_key="k")
    client = make_gateway_client(Task.FIX, gateway_cfg=cfg, hosted_cfg=hosted, local_cfg=local)
    assert isinstance(client, OllamaClient)  # never the hosted client, despite the default


def test_privacy_mode_refuses_loudly_instead_of_falling_back_to_hosted() -> None:
    cfg = GatewayConfig(default_backend=Backend.HOSTED, privacy_mode=True)
    hosted = LLMConfig(enabled=True, api_key="k")  # ready and available...
    with pytest.raises(PrivacyModeViolation, match="privacy mode"):
        make_gateway_client(Task.FIX, gateway_cfg=cfg, hosted_cfg=hosted, local_cfg=OllamaConfig())
    # ... proving the refusal is deliberate, not just "no client was configured at all"


def test_gateway_status_lists_every_known_task_and_leaks_no_secrets() -> None:
    cfg = GatewayConfig(default_backend=Backend.LOCAL, privacy_mode=False)
    hosted = LLMConfig(enabled=True, api_key="sk-ant-TOPSECRET0123456789")
    status = gateway_status(gateway_cfg=cfg, hosted_cfg=hosted, local_cfg=OllamaConfig())
    assert status["routes"] == {
        "fix": "local",
        "triage": "local",
        "hypotheses": "local",
        "copilot": "local",
        "attack_path": "local",
    }
    assert "TOPSECRET" not in json.dumps(status) and status["hosted"]["api_key_set"] is True


def test_gateway_config_from_env_reads_backend_and_privacy_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BULWARK_LLM_BACKEND", "local")
    monkeypatch.setenv("BULWARK_LLM_PRIVACY_MODE", "1")
    cfg = GatewayConfig.from_env()
    assert cfg.default_backend is Backend.LOCAL and cfg.privacy_mode is True


# ---- the local (Ollama) backend ------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *a: object) -> None:
        return None


def test_ollama_client_posts_chat_messages_and_reports_real_token_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_urlopen(req: Any, timeout: float) -> _FakeResponse:
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data)
        seen["timeout"] = timeout
        return _FakeResponse(
            {"message": {"content": "hi there"}, "prompt_eval_count": 7, "eval_count": 3}
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    c = OllamaClient(OllamaConfig(enabled=True, model="m1", base_url="http://x:1", timeout=5))
    got = c.complete("SYS", "USER")
    assert got == Completion("hi there", 10)
    assert seen["body"]["model"] == "m1" and seen["body"]["stream"] is False
    assert seen["body"]["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "USER"},
    ]
    assert seen["url"] == "http://x:1/api/chat" and seen["timeout"] == 5


def test_ollama_client_wraps_connection_failures_without_leaking_the_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(req: Any, timeout: float) -> None:
        raise urllib.error.URLError("connection refused: secret prompt was X")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    c = OllamaClient(OllamaConfig(enabled=True))
    from core.llm.client import LLMError

    with pytest.raises(LLMError) as exc:
        c.complete("SYS", "USER")
    assert "secret prompt" not in str(exc.value)


def test_make_ollama_client_is_none_unless_explicitly_enabled() -> None:
    assert make_ollama_client(OllamaConfig(enabled=False)) is None
    assert make_ollama_client(OllamaConfig(enabled=True)) is not None


def test_ollama_config_defaults_to_localhost_only() -> None:
    assert OllamaConfig().base_url == DEFAULT_BASE_URL == "http://localhost:11434"


# ---- path denylist --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [".env", ".env.production", "config/.env", "id_rsa", "keys/id_rsa", "server.pem",
     "certs/tls.key", "wallet.pfx", "app.jks", "id_ed25519.pub"],
)  # fmt: skip
def test_sensitive_paths_are_denylisted_by_default(path: str) -> None:
    assert is_denylisted(path)


@pytest.mark.parametrize("path", ["app.py", "src/users.js", "config/settings.py", "envfile.py"])
def test_ordinary_paths_are_not_denylisted(path: str) -> None:
    assert not is_denylisted(path)


def test_extra_denylist_patterns_from_env_are_additive_not_replacing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BULWARK_LLM_PATH_DENYLIST", "*.secretconf, notes.txt")
    patterns = denylist_from_env()
    assert set(DEFAULT_DENYLIST) <= set(patterns)
    assert is_denylisted("app.secretconf", patterns) and is_denylisted("notes.txt", patterns)
    assert is_denylisted(".env", patterns)  # the built-in list is never weakened


# ---- PII redaction (best-effort, degrades to a no-op when Presidio is unavailable) -----------------


def test_redact_pii_is_a_no_op_for_empty_or_whitespace_text() -> None:
    assert redact_pii("") == ("", 0)
    assert redact_pii("   ") == ("   ", 0)


def test_redact_pii_never_raises_even_if_the_analyzer_explodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import core.llm.pii as pii_mod

    def boom() -> None:
        raise RuntimeError("model not downloaded")

    monkeypatch.setattr(pii_mod, "_get_analyzer", boom)
    assert redact_pii("Contact Jane Doe at jane@example.com") == (
        "Contact Jane Doe at jane@example.com",
        0,
    )
