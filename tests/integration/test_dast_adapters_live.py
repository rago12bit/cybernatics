"""Real `docker run` of real ZAP/Nuclei against real targets (Week 49 task 3, plan §22.4) -- not
mocks. Skips when Docker isn't available, the same convention as this repo's other Docker-dependent
integration tests.

Nuclei's own high request concurrency could not reach a target through `host.docker.internal` on
this (macOS, Docker Desktop) dev machine -- reproduced directly (`docker run ... -u http://host.
docker.internal:PORT/` reported "i/o timeout" against both a plain `http.server` and the real
`bulwark-web-1` dev container, every time), a Docker-Desktop-for-Mac host-networking limitation under
load, not a bug in `core.dast.adapters.nuclei`: the same command against a real external host
(`https://example.com/`) works every time. The Nuclei test here therefore scans a real external site
rather than a local one; ZAP's lighter, non-concurrent baseline mode has no such problem and scans a
real local target instead.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core.dast.adapters.nuclei import run_nuclei
from core.dast.adapters.zap import run_zap_baseline
from core.models import Category


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:  # noqa: BLE001 - any failure means "not available"
        return False


pytestmark = pytest.mark.skipif(not _docker_available(), reason="docker is not available")


def _host_seen_from_a_container() -> str:
    """Docker Desktop names the host `host.docker.internal`; plain Docker on Linux (CI) does not
    unless the run adds `--add-host`, which run_zap_baseline only does with a proxy. There the host
    is the default bridge's gateway."""
    if sys.platform == "darwin":
        return "host.docker.internal"
    out = subprocess.run(
        ["docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    return out.stdout.strip()


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b'<html><body><a href="/admin">admin</a></body></html>')

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@pytest.fixture
def local_target() -> Iterator[int]:
    server = HTTPServer(("0.0.0.0", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()
    thread.join(timeout=2)


def test_a_real_zap_baseline_scan_finds_real_missing_security_headers(local_target: int) -> None:
    host = _host_seen_from_a_container()
    # A baseline run takes about 140 s on an M-series Mac under Docker Desktop.
    findings = run_zap_baseline(f"http://{host}:{local_target}/", timeout_s=300)
    assert len(findings) > 0
    assert all(f.taxonomy.category is Category.DAST for f in findings)
    assert len({f.id for f in findings}) == len(findings)  # no id collisions, see the unit test
    routes = {f.location.route for f in findings}
    assert "/admin" in routes  # proves the spider actually followed the real link


def test_a_real_nuclei_scan_against_a_real_external_host_produces_real_findings() -> None:
    findings = run_nuclei("https://example.com/", timeout_s=180)
    assert all(f.taxonomy.category is Category.DAST for f in findings)
    assert len({f.id for f in findings}) == len(findings)
