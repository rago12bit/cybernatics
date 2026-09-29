"""A local backend for the model gateway, via Ollama's own REST API (plan §21.1).

No SDK, no new dependency: Ollama's `/api/chat` is plain JSON over HTTP, so this uses the same
`urllib.request` approach `core.risk.feeds.http_get` already uses for outbound calls elsewhere in
this codebase -- the only difference is this one needs a POST body. Talks to `base_url` only, which
defaults to `localhost`: this is what makes privacy mode's "the code never leaves the machine"
guarantee true in the first place (`core/llm/gateway.py`).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from core.llm.client import Completion, LLMError

DEFAULT_MODEL = "llama3.1"
DEFAULT_BASE_URL = "http://localhost:11434"


@dataclass(frozen=True)
class OllamaConfig:
    enabled: bool = False
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout: float = (
        120.0  # local inference on modest hardware is slow; hosted's 30s default would starve it
    )

    @staticmethod
    def from_env() -> OllamaConfig:
        env = os.environ
        return OllamaConfig(
            enabled=env.get("BULWARK_LLM_LOCAL_ENABLED") == "1",
            base_url=env.get("BULWARK_LLM_LOCAL_URL", DEFAULT_BASE_URL),
            model=env.get("BULWARK_LLM_LOCAL_MODEL", DEFAULT_MODEL),
            timeout=float(env.get("BULWARK_LLM_LOCAL_TIMEOUT", "120")),
        )

    def status(self) -> dict[str, object]:
        return {"enabled": self.enabled, "model": self.model, "base_url": self.base_url}


class OllamaClient:
    model: str

    def __init__(self, cfg: OllamaConfig) -> None:
        self.model = cfg.model
        self._base_url = cfg.base_url.rstrip("/")
        self._timeout = cfg.timeout

    def complete(self, system: str, user: str) -> Completion:
        body = json.dumps(
            {
                "model": self.model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
        ).encode()
        req = urllib.request.Request(
            f"{self._base_url}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self._timeout
            ) as resp:  # noqa: S310 - local-only URL
                doc = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise LLMError(f"local model call failed ({type(exc).__name__})") from None
        text = (doc.get("message") or {}).get("content", "")
        tokens = int(doc.get("prompt_eval_count", 0) or 0) + int(doc.get("eval_count", 0) or 0)
        return Completion(text, tokens)


def make_ollama_client(cfg: OllamaConfig | None = None) -> OllamaClient | None:
    cfg = cfg or OllamaConfig.from_env()
    if not cfg.enabled:
        return None
    return OllamaClient(cfg)
