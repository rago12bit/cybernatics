"""Model access. Off by default: turning it on sends finding text off this machine (docs/llm-remediation.md).

The rest of the code depends only on `LLMClient`, so any provider (or a fake in tests) can sit behind it.
Configuration comes from the environment; the API key is never logged, printed or stored in a repr.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Protocol

DEFAULT_MODEL = "claude-sonnet-5"


class LLMError(RuntimeError):
    """The model call failed. The message never contains prompt or reply text."""


@dataclass(frozen=True)
class Completion:
    text: str
    tokens: int = 0  # input + output tokens the provider says this call used; 0 when unknown


class LLMClient(Protocol):
    model: str

    def complete(self, system: str, user: str) -> Completion: ...


@dataclass(frozen=True)
class LLMConfig:
    enabled: bool = False
    model: str = DEFAULT_MODEL
    api_key: str = field(default="", repr=False)
    timeout: float = 30.0
    max_tokens: int = 1500

    @staticmethod
    def from_env() -> LLMConfig:
        env = os.environ
        return LLMConfig(
            enabled=env.get("BULWARK_LLM_ENABLED") == "1",
            model=env.get("BULWARK_LLM_MODEL", DEFAULT_MODEL),
            api_key=env.get("BULWARK_LLM_API_KEY") or env.get("ANTHROPIC_API_KEY", ""),
            timeout=float(env.get("BULWARK_LLM_TIMEOUT", "30")),
            max_tokens=int(env.get("BULWARK_LLM_MAX_TOKENS", "1500")),
        )

    def status(self) -> dict[str, object]:
        """Safe to print: says whether a key exists, never what it is."""
        return {"enabled": self.enabled, "model": self.model, "api_key_set": bool(self.api_key)}


class AnthropicClient:
    def __init__(self, cfg: LLMConfig) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on the optional extra
            raise LLMError(
                "the 'anthropic' package is not installed: pip install 'bulwark-scan[llm]'"
            ) from exc
        self.model = cfg.model
        self._max_tokens = cfg.max_tokens
        self._sdk = anthropic
        self._client = anthropic.Anthropic(api_key=cfg.api_key, timeout=cfg.timeout, max_retries=1)

    def complete(self, system: str, user: str) -> Completion:
        try:
            msg = self._client.messages.create(
                model=self.model,
                max_tokens=self._max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except self._sdk.APIError as exc:
            raise LLMError(f"model call failed ({type(exc).__name__})") from None
        except Exception as exc:  # noqa: BLE001 - timeouts, connection errors, anything else
            raise LLMError(f"model call failed ({type(exc).__name__})") from None
        text = "".join(getattr(b, "text", "") for b in msg.content)
        usage = getattr(msg, "usage", None)
        tokens = (getattr(usage, "input_tokens", 0) or 0) + (
            getattr(usage, "output_tokens", 0) or 0
        )
        return Completion(text, tokens)


def make_client(cfg: LLMConfig | None = None) -> LLMClient | None:
    """A client when the feature is enabled AND a key is present; otherwise None (static text is used)."""
    cfg = cfg or LLMConfig.from_env()
    if not cfg.enabled or not cfg.api_key:
        return None
    return AnthropicClient(cfg)
