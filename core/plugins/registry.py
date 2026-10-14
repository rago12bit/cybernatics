"""Plugin discovery and org-aware resolution (Week 51 task 1, plan §23).

Discovery uses Python's standard `importlib.metadata.entry_points()` -- the first use of entry-point
discovery anywhere in this codebase (pyproject.toml otherwise only has `[project.scripts]`), so a
third-party plugin package needs no Bulwark-specific packaging mechanism, just a normal entry point:

    # pyproject.toml of a plugin package
    [project.entry-points."bulwark.scanner_adapters"]
    acme-trivy-plus = "acme_trivy_plus.plugin:manifest"

`acme_trivy_plus.plugin.manifest` must be a `core.plugins.manifest.PluginManifest` instance (or a
zero-argument callable returning one, for plugins that need to build their adapter lazily).

Resolution never trusts discovery alone: `resolve_adapters` additionally checks the calling
organization's own allowlist (`core.persistence.repo.is_plugin_allowed`) and re-verifies the
plugin's declared Sigstore identity against its image (`core.plugins.signing.verify_plugin_image`)
on every call -- being installed next to Bulwark is necessary but never sufficient for a plugin to
run, and a signature is checked at the moment of use, not cached from whenever it was allowlisted.
"""

from __future__ import annotations

import copy
import dataclasses
import logging
from collections.abc import Mapping
from importlib.metadata import EntryPoint, entry_points
from typing import TYPE_CHECKING

from core.adapters import ToolAdapter
from core.persistence import repo
from core.plugins.manifest import PluginManifest
from core.plugins.signing import pinned_reference, verify_plugin_image

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "bulwark.scanner_adapters"


class PluginError(RuntimeError):
    """Base for every reason a requested plugin tool cannot be resolved right now."""


class PluginNotFoundError(PluginError):
    pass


class PluginNotAllowedError(PluginError):
    pass


def _load_manifest(ep: EntryPoint) -> PluginManifest | None:
    try:
        obj = ep.load()
        manifest = obj() if callable(obj) and not isinstance(obj, PluginManifest) else obj
    except Exception as exc:  # noqa: BLE001 - one broken plugin package must never break discovery
        log.warning("plugin %r failed to load: %s", ep.name, exc)
        return None
    if not isinstance(manifest, PluginManifest):
        log.warning("plugin %r entry point did not return a PluginManifest", ep.name)
        return None
    return manifest


def discover_plugins() -> dict[str, PluginManifest]:
    """Every installed package's `bulwark.scanner_adapters` entry point, keyed by the tool name its
    adapter registers under (`PluginManifest.plugin_name`). A plugin that fails to import or load is
    logged and skipped, never allowed to take down discovery for every other plugin -- the same
    safe-parse philosophy `core.adapters.helpers.JsonAdapter` already applies to one bad tool-output
    record."""
    found: dict[str, PluginManifest] = {}
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        manifest = _load_manifest(ep)
        if manifest is None:
            continue
        if manifest.plugin_name in found:
            log.warning(
                "duplicate plugin tool name %r from %r, keeping the first one found",
                manifest.plugin_name,
                ep.value,
            )
            continue
        found[manifest.plugin_name] = manifest
    return found


def resolve_adapters(
    names: list[str], builtin: Mapping[str, ToolAdapter], org_id: str | None, s: Session | None
) -> dict[str, ToolAdapter]:
    """Returns one `ToolAdapter` per requested name. A built-in name is always included unchanged
    -- built-ins are trusted by definition, with no allowlist or signature step. A plugin name
    requires both `org_id` and `s` (there is no "trust every org" fallback the way the legacy
    shared token has for read access elsewhere): with neither, every plugin name raises
    `PluginNotAllowedError`, the same fail-closed default `core.persistence.repo.is_plugin_allowed`
    itself documents.

    Raises `PluginNotFoundError` for a name that is neither built in nor discovered, and
    `PluginSignatureError` (from core.plugins.signing) if a genuinely allowlisted plugin's current
    image no longer carries a valid signature from its declared publisher -- a drift this re-check
    catches even though nothing about the allowlist row itself changed.
    """
    out: dict[str, ToolAdapter] = {}
    plugins: dict[str, PluginManifest] | None = None
    for name in names:
        if name in builtin:
            out[name] = builtin[name]
            continue
        if plugins is None:
            plugins = discover_plugins()
        manifest = plugins.get(name)
        if manifest is None:
            raise PluginNotFoundError(f"no built-in or installed plugin tool named {name!r}")
        if org_id is None or s is None or not repo.is_plugin_allowed(s, org_id, name):
            raise PluginNotAllowedError(f"plugin {name!r} is not allowlisted for this organization")
        image = manifest.adapter.spec.image
        signatures = verify_plugin_image(
            image, manifest.certificate_identity, manifest.certificate_oidc_issuer
        )
        # Run exactly what was verified: the image by its signed digest, not by its tag again.
        adapter = copy.copy(manifest.adapter)
        adapter.spec = dataclasses.replace(
            manifest.adapter.spec, image=pinned_reference(image, signatures)
        )
        out[name] = adapter
    return out
