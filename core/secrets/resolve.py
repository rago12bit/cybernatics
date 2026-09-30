"""Resolves a secret from OpenBao's KV store when configured, falling back to a plain environment
variable otherwise (Week 47 task 4, plan §22.2, ADR-0033) -- the same "off means off" posture as
every other optional integration in this project: unset BULWARK_OPENBAO_ADDR/BULWARK_OPENBAO_TOKEN
and every secret keeps coming from its env var exactly as before this task, unchanged behavior for
every existing deployment.
"""

from __future__ import annotations

import logging
import os

from core.secrets.openbao import OpenBaoClient, OpenBaoError

log = logging.getLogger(__name__)


def resolve_secret(env_var: str, *, kv_path: str, kv_key: str = "value") -> str:
    """The value of `env_var`, preferring OpenBao's KV store at `secret/data/<kv_path>` when
    OpenBao is configured (`BULWARK_OPENBAO_ADDR`/`BULWARK_OPENBAO_TOKEN` both set) and actually has
    that secret. An unreachable or misconfigured OpenBao falls back to the environment variable
    rather than failing the whole process -- a secret temporarily unreachable in OpenBao must not
    take down the service that needs it; it only means running on whatever `env_var` last held.
    """
    addr = os.environ.get("BULWARK_OPENBAO_ADDR", "")
    token = os.environ.get("BULWARK_OPENBAO_TOKEN", "")
    if addr and token:
        try:
            value = OpenBaoClient(addr=addr, token=token).get_secret(kv_path, key=kv_key)
            if value is not None:
                return value
        except OpenBaoError:
            log.warning(
                "could not reach OpenBao for secret %r; falling back to %s", kv_path, env_var
            )
    return os.environ.get(env_var, "")
