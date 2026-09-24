"""Runtime configuration from environment variables (12-factor)."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


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
            api_token=os.environ.get("BULWARK_API_TOKEN", ""),
            workdir=workdir,
            upload_dir=workdir / "uploads",
            max_upload_bytes=int(os.environ.get("BULWARK_MAX_UPLOAD_BYTES", 100 * 1024 * 1024)),
        )


def scratch_dir() -> Path:
    """Base dir for per-scan temp workspaces.

    Must be a path that is identical on the host and inside the worker container, because scanner
    containers are launched via the host Docker daemon and bind-mount these paths.
    """
    d = Settings.from_env().workdir / "tmp"
    d.mkdir(parents=True, exist_ok=True)
    return d
