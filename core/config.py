"""Runtime configuration from environment variables (12-factor)."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.secrets.resolve import resolve_secret


@dataclass(frozen=True)
class Settings:
    database_url: str
    redis_url: str
    s3_endpoint: str | None
    s3_access_key: str
    s3_secret_key: str
    s3_bucket: str
    api_token: str
    workdir: Path
    upload_dir: Path
    max_upload_bytes: int
    cors_origins: tuple[str, ...] = ("http://localhost:3000",)
    # GitHub App integration (Week 30, ADR-0017). All empty by default: the integration is simply
    # off (the webhook endpoint 404s) until a real App is registered and these are set.
    github_app_id: str = ""
    github_app_private_key: str = (
        ""  # PEM; `\n` escapes are unescaped, since most secret stores flatten them
    )
    github_webhook_secret: str = ""
    # Envelope encryption (Week 47, plan §22.2, ADR-0032). Both empty by default: callers that need
    # a core.secrets.openbao.OpenBaoClient construct it explicitly and get a clear error at the
    # point of use if these are unset, the same "off means off, not a silent no-op" posture as the
    # GitHub App integration above.
    openbao_addr: str = ""
    openbao_token: str = ""
    # Cost-per-scan dashboard (plan §23, Week 50): both tunable per deployment, since neither is
    # knowable from inside this codebase -- see core/observability/cost.py's own docstring for why
    # the defaults are explicitly placeholders, not real billing figures.
    compute_cost_per_second_usd: float = 0.0003
    llm_cost_per_1k_tokens_usd: float | None = (
        None  # None -> core.observability.cost's per-model table
    )
    # Hosted mode (Week 53, ADR-0038): Semgrep's community/Pro rules are licensed for internal
    # business use only (ADR-006), which offering scans as a service to other people is not. False
    # (self-host, the only mode this project ships configured for today) changes nothing; a real
    # hosted deployment sets this to switch the SAST default to Opengrep and refuse "semgrep".
    hosted_mode: bool = False
    # Uploaded reports are parsed in the scanner sandbox (ADR-0040, `core.imports.parsers.sandbox`).
    # True is the default and the only safe production setting; False parses in the worker's own
    # process and exists for tests and for local development without Docker.
    ingest_sandbox: bool = True

    @staticmethod
    def from_env() -> Settings:
        workdir = Path(os.environ.get("BULWARK_WORKDIR", tempfile.gettempdir())) / "bulwark-work"
        return Settings(
            database_url=os.environ.get("BULWARK_DATABASE_URL", "sqlite:///bulwark.db"),
            redis_url=os.environ.get("BULWARK_REDIS_URL", "redis://localhost:6379/0"),
            s3_endpoint=os.environ.get("BULWARK_S3_ENDPOINT") or None,
            s3_access_key=os.environ.get("BULWARK_S3_ACCESS_KEY", ""),
            s3_secret_key=os.environ.get("BULWARK_S3_SECRET_KEY", ""),
            s3_bucket=os.environ.get("BULWARK_S3_BUCKET", "bulwark-artifacts"),
            api_token=resolve_secret("BULWARK_API_TOKEN", kv_path="bulwark/api-token"),
            workdir=workdir,
            upload_dir=workdir / "uploads",
            max_upload_bytes=int(os.environ.get("BULWARK_MAX_UPLOAD_BYTES", 100 * 1024 * 1024)),
            cors_origins=tuple(
                o.strip()
                for o in os.environ.get("BULWARK_CORS_ORIGINS", "http://localhost:3000").split(",")
                if o.strip()
            ),
            github_app_id=os.environ.get("BULWARK_GITHUB_APP_ID", ""),
            github_app_private_key=resolve_secret(
                "BULWARK_GITHUB_APP_PRIVATE_KEY", kv_path="bulwark/github-app-private-key"
            ).replace("\\n", "\n"),
            github_webhook_secret=resolve_secret(
                "BULWARK_GITHUB_WEBHOOK_SECRET", kv_path="bulwark/github-webhook-secret"
            ),
            openbao_addr=os.environ.get("BULWARK_OPENBAO_ADDR", ""),
            openbao_token=os.environ.get("BULWARK_OPENBAO_TOKEN", ""),
            compute_cost_per_second_usd=float(
                os.environ.get("BULWARK_COMPUTE_COST_PER_SECOND_USD", 0.0003)
            ),
            llm_cost_per_1k_tokens_usd=(
                float(os.environ["BULWARK_LLM_COST_PER_1K_TOKENS_USD"])
                if "BULWARK_LLM_COST_PER_1K_TOKENS_USD" in os.environ
                else None
            ),
            hosted_mode=os.environ.get("BULWARK_HOSTED_MODE", "").strip().lower()
            in ("1", "true", "yes"),
            ingest_sandbox=os.environ.get("BULWARK_INGEST_SANDBOX", "1").strip().lower()
            not in ("0", "false", "no"),
        )


def scratch_dir() -> Path:
    """Base dir for per-scan temp workspaces.

    Must be a path that is identical on the host and inside the worker container, because scanner
    containers are launched via the host Docker daemon and bind-mount these paths.
    """
    d = Settings.from_env().workdir / "tmp"
    d.mkdir(parents=True, exist_ok=True)
    return d
