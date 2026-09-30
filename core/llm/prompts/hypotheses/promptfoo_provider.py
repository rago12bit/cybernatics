"""promptfoo custom provider for the Hypotheses lane (plan §21.4), mirroring
core/llm/prompts/fix/promptfoo_provider.py and core/llm/prompts/triage/promptfoo_provider.py: routes
eval prompts through the real model gateway (`core.llm.gateway`, `Task.HYPOTHESES`).
"""

from __future__ import annotations

from typing import Any

from core.hypotheses.prompt import SYSTEM
from core.llm.client import LLMConfig
from core.llm.gateway import Backend, GatewayConfig, Task, make_gateway_client
from core.llm.ollama_client import OllamaConfig


def _configs(cfg: dict[str, Any]) -> tuple[GatewayConfig, LLMConfig, OllamaConfig]:
    backend = Backend(cfg.get("backend", "local"))
    hosted = LLMConfig.from_env()
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
            timeout=float(cfg.get("request_timeout_s", OllamaConfig.timeout)),
        ),
    )


def call_api(prompt: str, options: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    gw_cfg, hosted_cfg, local_cfg = _configs((options or {}).get("config") or {})
    client = make_gateway_client(
        Task.HYPOTHESES, gateway_cfg=gw_cfg, hosted_cfg=hosted_cfg, local_cfg=local_cfg
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
