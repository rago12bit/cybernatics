"""The model gateway: one interface, several backends, chosen per task (plan §21.1).

`client.make_client()` picks the single hosted provider Anthropic implementation; `ollama_client
.make_ollama_client()` does the same for a local one. Neither knows the other exists. This module is
the one place that decides which of them a given task should use, so privacy mode and per-task model
choice live in one spot instead of being re-decided at every call site (the API endpoint, the CLI).

Three tasks have a real caller: `fix` (`core.llm.service.suggest`, used from `POST
/scans/{id}/suggestion` and `bulwark llm suggest`), `triage` (`core.triage_assistant.service.assess`,
Week 43, plan §21.3), and `hypotheses` (`core.hypotheses.service.assess_candidate`, Week 43, plan
§21.4). A copilot task lands in Week 44 and will register its own route the same way -- `Task` and
the per-task override below are genuinely keyed by task name, not hardcoded to `fix`.

Privacy mode (`BULWARK_LLM_PRIVACY_MODE=1`) forces every task onto the local backend and refuses --
loudly, never a silent fallback to hosted -- when no local model is configured. A silent fallback
would quietly defeat the one guarantee privacy mode exists to make ("the code never leaves the
machine").
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

from core.llm.client import LLMClient, LLMConfig, LLMError, make_client
from core.llm.ollama_client import OllamaConfig, make_ollama_client


class Task(str, Enum):
    FIX = "fix"  # core.llm.service.suggest
    TRIAGE = "triage"  # core.triage_assistant.service.assess (plan §21.3)
    HYPOTHESES = "hypotheses"  # core.hypotheses.service.assess_candidate (plan §21.4)


class Backend(str, Enum):
    HOSTED = "hosted"
    LOCAL = "local"


class PrivacyModeViolation(LLMError):
    """Privacy mode is on but no local backend is ready; refuses rather than silently using a
    hosted model, which would defeat the guarantee privacy mode promises."""


@dataclass(frozen=True)
class GatewayConfig:
    default_backend: Backend = Backend.HOSTED
    privacy_mode: bool = False

    @staticmethod
    def from_env() -> GatewayConfig:
        env = os.environ
        return GatewayConfig(
            default_backend=Backend(env.get("BULWARK_LLM_BACKEND", "hosted")),
            privacy_mode=env.get("BULWARK_LLM_PRIVACY_MODE") == "1",
        )

    def status(self) -> dict[str, object]:
        return {"default_backend": self.default_backend.value, "privacy_mode": self.privacy_mode}


def _route(task: Task, cfg: GatewayConfig) -> Backend:
    """The per-task override env var, e.g. `BULWARK_LLM_ROUTE_FIX=local`; else the gateway's default."""
    override = os.environ.get(f"BULWARK_LLM_ROUTE_{task.value.upper()}")
    return Backend(override) if override else cfg.default_backend


def make_gateway_client(
    task: Task,
    *,
    gateway_cfg: GatewayConfig | None = None,
    hosted_cfg: LLMConfig | None = None,
    local_cfg: OllamaConfig | None = None,
) -> LLMClient | None:
    """`None` means "no model for this task right now" (static text is used) -- same contract
    `make_client`/`make_ollama_client` already have. Raises only for the one case that must never be
    silent: privacy mode on, no local backend ready."""
    gateway_cfg = gateway_cfg or GatewayConfig.from_env()
    backend = Backend.LOCAL if gateway_cfg.privacy_mode else _route(task, gateway_cfg)
    if backend is Backend.LOCAL:
        client = make_ollama_client(local_cfg or OllamaConfig.from_env())
        if client is None and gateway_cfg.privacy_mode:
            raise PrivacyModeViolation(
                "privacy mode is on (BULWARK_LLM_PRIVACY_MODE=1) but no local model is configured: "
                "set BULWARK_LLM_LOCAL_ENABLED=1 (and optionally BULWARK_LLM_LOCAL_MODEL/_URL), or "
                "turn privacy mode off"
            )
        return client
    return make_client(hosted_cfg or LLMConfig.from_env())


def gateway_status(
    gateway_cfg: GatewayConfig | None = None,
    hosted_cfg: LLMConfig | None = None,
    local_cfg: OllamaConfig | None = None,
) -> dict[str, object]:
    """Safe to print: which backend each known task would actually use, plus each backend's own
    (secret-free) status -- never whether a call would succeed, only how it would be routed."""
    gateway_cfg = gateway_cfg or GatewayConfig.from_env()
    routes = {
        t.value: (Backend.LOCAL if gateway_cfg.privacy_mode else _route(t, gateway_cfg)).value
        for t in Task
    }
    return {
        **gateway_cfg.status(),
        "routes": routes,
        "hosted": (hosted_cfg or LLMConfig.from_env()).status(),
        "local": (local_cfg or OllamaConfig.from_env()).status(),
    }
