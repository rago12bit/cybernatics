"""Real Docker, running a third-party package's own ToolAdapter through the exact sandboxed path a
built-in scanner uses -- not mocks (Week 51 task 1, plan §23). Needs
`pip install -e examples/bulwark-plugin-demo` (done once by this project's dev setup and by
.github/workflows/ci.yml's own install step) so `bulwark_plugin_demo` is a genuinely separate,
independently-installed package, not code imported from Bulwark's own tree.

Two real things proven here:
1. `DemoAdapter`, discovered via a real entry point, runs through `core.scan.execute_tool` ->
   `core.runner.run_tool` -> a real `docker run` of `bulwark/bandit:1.7.10` under the same strict
   sandbox flags (`--network=none --read-only --cap-drop=ALL --user=10001:10001`, etc.) every
   built-in scanner runs under, and produces real findings from a real file this test writes.
2. `core.plugins.registry.resolve_adapters` genuinely refuses to resolve this exact plugin, because
   `bulwark/bandit:1.7.10` (unlike the identity its manifest *declares*, a real signed public image
   used only to prove the signing code path works) carries no Sigstore signature of its own -- the
   fail-closed behavior tests/unit/test_plugin_registry.py exercises with a mock, here exercised
   against the real image and the real cosign binary.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import Organization
from core.plugins.registry import resolve_adapters
from core.plugins.signing import PluginSignatureError
from core.scan import ADAPTERS, execute_tool
from core.tenancy import DEFAULT_ORG_ID


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:  # noqa: BLE001 - any failure means "not available"
        return False


def _demo_plugin_installed() -> bool:
    try:
        import bulwark_plugin_demo  # noqa: F401

        return True
    except ImportError:
        return False


def _bandit_image_present() -> bool:
    try:
        out = subprocess.run(
            ["docker", "image", "inspect", "bulwark/bandit:1.7.10"],
            capture_output=True, timeout=10,
        )  # fmt: skip
        return out.returncode == 0
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not (_docker_available() and _demo_plugin_installed() and _bandit_image_present()),
    reason="docker, the demo plugin package, or the bulwark/bandit image is not available -- see "
    "examples/bulwark-plugin-demo/README.md and docker/bandit",
)


def test_a_third_party_packages_adapter_runs_through_the_real_sandbox(tmp_path: Path) -> None:
    from bulwark_plugin_demo.adapter import DemoAdapter

    (tmp_path / "app.py").write_text(
        'import subprocess\npassword = "hunter2"\nsubprocess.call("ls", shell=True)\n'
    )
    outcome = execute_tool(
        "demo-bandit-plugin", tmp_path, adapters={"demo-bandit-plugin": DemoAdapter()}
    )
    assert outcome.status == "ok"
    titles = {f.title for f in outcome.findings}
    assert any("hardcoded password" in t.lower() for t in titles)
    assert any("shell=true" in t.lower() for t in titles)
    assert all(f.id.startswith("demo-bandit-plugin:") for f in outcome.findings)


def test_resolve_adapters_refuses_the_demo_plugins_actual_unsigned_image(
    sessions: sessionmaker[Session],
) -> None:
    from bulwark_plugin_demo.plugin import manifest

    assert manifest.adapter.spec.image == "bulwark/bandit:1.7.10"  # never Sigstore-signed
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_plugin_allowed(
            s, DEFAULT_ORG_ID, "demo-bandit-plugin", enabled=True, allowed_by="test"
        )
        with pytest.raises(PluginSignatureError):
            resolve_adapters(["demo-bandit-plugin"], ADAPTERS, DEFAULT_ORG_ID, s)
