"""Plugin SDK: third-party scanner adapters (Week 51 task 1, plan §23). See core/plugins/registry.py
for discovery and resolution, core/plugins/signing.py for Sigstore verification, and
core/plugins/conformance.py for the golden-file conformance kit a plugin author's own tests run."""

from __future__ import annotations

from core.plugins.manifest import PluginManifest
from core.plugins.registry import (
    PluginError,
    PluginNotAllowedError,
    PluginNotFoundError,
    discover_plugins,
    resolve_adapters,
)

__all__ = [
    "PluginError",
    "PluginManifest",
    "PluginNotAllowedError",
    "PluginNotFoundError",
    "discover_plugins",
    "resolve_adapters",
]
