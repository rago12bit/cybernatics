"""The entry point this package declares in pyproject.toml. A real plugin would set
`certificate_identity` to its own release workflow's identity -- see this package's README for why
this demo instead points at a well-known public Sigstore demo image (stefanprodan/podinfo)'s
identity rather than this adapter's own `bulwark/bandit:1.7.10` image, which carries no Sigstore
signature at all: `core.plugins.signing` would correctly refuse either mismatch, and
tests/integration/test_plugin_sandbox_execution_live.py demonstrates exactly that refusal for real.
"""

from __future__ import annotations

from bulwark_plugin_demo.adapter import DemoAdapter
from core.plugins.manifest import PluginManifest

manifest = PluginManifest(
    adapter=DemoAdapter(),
    package_name="bulwark-plugin-demo",
    package_version="0.1.0",
    certificate_identity=(
        "https://github.com/stefanprodan/podinfo/.github/workflows/release.yml@refs/tags/6.4.0"
    ),
    certificate_oidc_issuer="https://token.actions.githubusercontent.com",
)
