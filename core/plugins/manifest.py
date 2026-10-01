"""The PluginManifest a third-party scanner-adapter package declares (Week 51 task 1, plan §23).

A `ToolAdapter` alone (`core.adapters.ToolAdapter`) is just parsing logic plus a `ToolSpec` -- it
has no notion of *who* published it. `PluginManifest` is the extra identity wrapper a third-party
package exposes through its entry point, naming the exact Sigstore keyless identity
(`core.plugins.signing`) that must have signed `adapter.spec.image` before it is ever allowed to
run.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.adapters import ToolAdapter


@dataclass(frozen=True)
class PluginManifest:
    """`certificate_identity`/`certificate_oidc_issuer` are matched against the Sigstore Fulcio
    certificate embedded in the transparency-log entry for `adapter.spec.image` -- the same two
    fields `cosign verify --certificate-identity=... --certificate-oidc-issuer=...` takes. A plugin
    author who builds their image in GitHub Actions would set `certificate_identity` to their
    workflow's own job identity (e.g.
    "https://github.com/<org>/<repo>/.github/workflows/release.yml@refs/heads/main") and
    `certificate_oidc_issuer` to "https://token.actions.githubusercontent.com" -- proving the image
    was built by *that* CI pipeline, not merely uploaded by whoever holds registry push rights."""

    adapter: ToolAdapter
    package_name: str  # the installed distribution's name, e.g. "acme-trivy-plus"
    package_version: str
    certificate_identity: str
    certificate_oidc_issuer: str

    @property
    def plugin_name(self) -> str:
        """The tool name this plugin registers under -- same identifier space as a built-in's
        `ToolSpec.name`, so API responses and `scan.tools` never need a separate "is this a plugin"
        field to tell the two apart."""
        return self.adapter.spec.name
