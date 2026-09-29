"""promptfoo custom provider (plan §21.1): routes eval prompts through the REAL model gateway
(`core.llm.gateway`), not a reimplementation, so a promptfoo run exercises the exact backend
selection logic production uses.

Backend choice comes from this provider's own `config:` block in promptfooconfig.yaml, not ambient
`BULWARK_LLM_*` env vars: promptfoo's Python provider runs in a persistent worker process, and a var
exported in the invoking shell after that worker starts does not reliably reach it (confirmed while
building this suite -- the obvious env-var-driven design silently saw nothing). A self-contained
`config:` block is what makes a `promptfoo eval` run reproducible regardless of that.

Requires `bulwark-scan` importable on this interpreter (`pip install -e .`, or point promptfoo at
your venv with `pythonExecutable` / the `PROMPTFOO_PYTHON` env var) -- it calls straight into
`core.llm`, not a subprocess or HTTP call to Bulwark itself.
"""

from __future__ import annotations

from typing import Any

from core.llm.client import LLMConfig
from core.llm.gateway import Backend, GatewayConfig, Task, make_gateway_client
from core.llm.ollama_client import OllamaConfig
from core.llm.prompt import SYSTEM


def _configs(cfg: dict[str, Any]) -> tuple[GatewayConfig, LLMConfig, OllamaConfig]:
    backend = Backend(cfg.get("backend", "local"))
    hosted = LLMConfig.from_env()  # only its api_key (never printed) is used as a fallback below
    return (
        GatewayConfig(default_backend=backend, privacy_mode=False),
        LLMConfig(
            enabled=backend == Backend.HOSTED,
            model=cfg.get("model", LLMConfig.model),
            api_key=cfg.get("api_key") or hosted.api_key,
        ),
        OllamaConfig(
            enabled=backend == Backend.LOCAL,
            model=cfg.get("model", OllamaConfig.model),
            base_url=cfg.get("base_url", OllamaConfig.base_url),
            # NOT named "timeout": promptfoo's OWN Python-worker config already reserves that key
            # (milliseconds, caps the whole call) -- reusing it silently fed our seconds-based value
            # in as promptfoo's timeout instead, which is exactly how this broke while building it.
            timeout=float(cfg.get("request_timeout_s", OllamaConfig.timeout)),
        ),
    )


def call_api(prompt: str, options: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    gw_cfg, hosted_cfg, local_cfg = _configs((options or {}).get("config") or {})
    client = make_gateway_client(
        Task.FIX, gateway_cfg=gw_cfg, hosted_cfg=hosted_cfg, local_cfg=local_cfg
    )
    if client is None:
        return {
            "error": (
                "no model routed: for backend 'local' pull an Ollama model and set it in this "
                "provider's config; for 'hosted' set config.api_key or export BULWARK_LLM_API_KEY"
            )
        }
    try:
        completion = client.complete(SYSTEM, prompt)
    except Exception as exc:  # noqa: BLE001 - report as a normal eval failure, not a crash
        return {"error": f"model call failed: {type(exc).__name__}: {exc}"}
    return {"output": completion.text, "tokenUsage": {"total": completion.tokens}}
