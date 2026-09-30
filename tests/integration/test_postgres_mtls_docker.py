"""Postgres mTLS end-to-end (Week 47 task 3, plan §22.2, ADR-0033): a REAL image built from
docker/postgres, REAL certificates from scripts/gen-mtls-certs.sh, and REAL connection attempts --
not mocked. Every scenario here was worked out by hand against this exact image before being written
as a test; see docs/v2-week47-verification.md. Manages its own lifecycle (build, generate certs,
run, tear down) so it needs no setup beyond Docker. Skips everywhere Docker isn't available.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "bulwark/postgres:16-pgvector-mtls-test"


def _docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(not _docker_ready(), reason="docker not available")


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("mtls-certs")
    subprocess.run(
        ["./scripts/gen-mtls-certs.sh", str(out)], cwd=ROOT, check=True, capture_output=True
    )
    return out


@pytest.fixture(scope="module")
def pg(certs: Path) -> Iterator[str]:
    """Builds the real image and starts one container for every test in this module -- the image
    build (a few seconds) and container boot only need to happen once, and none of these tests
    mutate state the others depend on."""
    subprocess.run(
        ["docker", "build", "-t", IMAGE, "docker/postgres"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    name = f"bulwark-pg-mtls-test-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker", "run", "-d", "--name", name, "-p", "127.0.0.1::5432",
            "-e", "POSTGRES_USER=bulwark", "-e", "POSTGRES_PASSWORD=testpw",
            "-e", "POSTGRES_DB=bulwark", "-e", "TEMPORAL_DB_PASSWORD=temporal-pw",
            "-v", f"{certs}:/certs-in:ro", IMAGE,
        ],  # fmt: skip
        check=True,
        capture_output=True,
    )
    try:
        port = (
            subprocess.run(
                ["docker", "port", name, "5432/tcp"], check=True, capture_output=True, text=True
            )
            .stdout.strip()
            .rsplit(":", 1)[-1]
        )
        _wait_until_ready(port)
        # Migrated once, here, before any test runs: bulwark_api/bulwark_worker/bulwark_fixagent
        # don't exist until migration 0020 creates them, and bulwark_app doesn't become NOLOGIN
        # until then either -- every test in this module needs that state already in place.
        _migrate_to_head(port, certs)
        yield port
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


def _connect(port: str, **kw: Any) -> psycopg.Connection:
    return psycopg.connect(
        f"host=localhost port={int(port)} dbname=bulwark connect_timeout=5", **kw
    )


def _wait_until_ready(port: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _connect(port, user="bulwark_nonexistent", sslmode="require").close()
        except psycopg.OperationalError as exc:
            last_error = exc
            # psycopg tries both IPv4 and IPv6 and concatenates every attempt's message into one
            # exception, so "connection refused" from a stale/unready IPv6 path can appear ALONGSIDE
            # a real Postgres response on IPv4 in the very same exception -- check for a definitive
            # "the server answered" signal, not the absence of "refused" anywhere in the string.
            if "requires a valid client certificate" in str(exc):
                return
            time.sleep(0.3)
    raise TimeoutError(f"postgres never became ready: {last_error}")


def test_a_service_role_connects_with_its_own_certificate(pg: str, certs: Path) -> None:
    conn = _connect(
        pg, user="bulwark_worker", sslmode="verify-ca", sslrootcert=str(certs / "ca.crt"),
        sslcert=str(certs / "client_bulwark_worker.crt"), sslkey=str(certs / "client_bulwark_worker.key"),
    )  # fmt: skip
    with conn.cursor() as cur:
        cur.execute("SELECT current_user")
        assert cur.fetchone() == ("bulwark_worker",)
    conn.close()


def test_no_client_certificate_is_rejected(pg: str) -> None:
    with pytest.raises(psycopg.OperationalError, match="valid client certificate"):
        _connect(pg, user="bulwark_worker", sslmode="require")


def test_a_certificate_for_a_different_role_is_rejected(pg: str, certs: Path) -> None:
    """bulwark_api's certificate must not authenticate as bulwark_worker -- the CN has to match the
    role being connected as, not merely be signed by a trusted CA."""
    with pytest.raises(psycopg.OperationalError, match="certificate authentication failed"):
        _connect(
            pg, user="bulwark_worker", sslmode="verify-ca", sslrootcert=str(certs / "ca.crt"),
            sslcert=str(certs / "client_bulwark_api.crt"), sslkey=str(certs / "client_bulwark_api.key"),
        )  # fmt: skip


def test_bulwark_app_cannot_log_in_directly_after_migration_0020(pg: str, certs: Path) -> None:
    """bulwark_app still holds every grant (bulwark_worker/_api/_fixagent inherit it via role
    membership) but is NOLOGIN as of migration 0020 (already applied by the `pg` fixture) --
    nothing can connect directly as it."""
    with pytest.raises(psycopg.OperationalError, match="not permitted to log in|certificate auth"):
        _connect(
            pg, user="bulwark_app", sslmode="verify-ca", sslrootcert=str(certs / "ca.crt"),
            sslcert=str(certs / "client_bulwark_api.crt"), sslkey=str(certs / "client_bulwark_api.key"),
        )  # fmt: skip


def test_temporal_svc_authenticates_by_password_with_no_certificate(pg: str) -> None:
    """The one disclosed carve-out (docker/postgres/pg_hba.conf): Temporal's third-party auto-setup
    image cannot present a client certificate, so its dedicated role uses password auth instead --
    and only that role; every Bulwark-owned role still requires a certificate."""
    conn = _connect(pg, user="temporal_svc", password="temporal-pw", sslmode="require")
    with conn.cursor() as cur:
        cur.execute("SELECT current_user")
        assert cur.fetchone() == ("temporal_svc",)
    conn.close()

    with pytest.raises(psycopg.OperationalError, match="password authentication failed"):
        _connect(pg, user="temporal_svc", password="wrong-password", sslmode="require")


def _migrate_to_head(port: str, certs: Path) -> None:
    import os
    import sys

    env = {
        **os.environ,
        "BULWARK_DATABASE_URL": (
            f"postgresql+psycopg://bulwark@localhost:{port}/bulwark?sslmode=verify-ca"
            f"&sslrootcert={certs / 'ca.crt'}&sslcert={certs / 'client_bulwark.crt'}"
            f"&sslkey={certs / 'client_bulwark.key'}"
        ),
        "APP_DB_PASSWORD": "app-pw",
    }
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT, env=env, check=True, capture_output=True,
    )  # fmt: skip
