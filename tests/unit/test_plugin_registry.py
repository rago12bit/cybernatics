"""core.plugins.registry: discovery and org-aware resolution (Week 51 task 1, plan §23).

Entry-point discovery is faked here via monkeypatch (fast, deterministic, no real package install
needed) -- the real, installed-package discovery path is proven in
tests/unit/test_plugin_conformance.py and the live integration tests, which both use the actual
installed examples/bulwark-plugin-demo package.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.adapters.base import RepoContext, ToolSpec
from core.adapters.helpers import JsonAdapter
from core.models import Finding
from core.persistence import repo
from core.persistence.models import Organization
from core.plugins import registry
from core.plugins.manifest import PluginManifest
from core.plugins.registry import (
    PluginNotAllowedError,
    PluginNotFoundError,
    discover_plugins,
    resolve_adapters,
)
from core.plugins.signing import PluginSignatureError
from core.tenancy import DEFAULT_ORG_ID


class _FakeAdapter(JsonAdapter):
    spec = ToolSpec("fake-plugin", "example/fake:1", frozenset({"sast"}), frozenset({"python"}))

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return []

    def records(self, doc: Any) -> list[dict[str, Any]]:
        return []

    def to_finding(self, r: dict[str, Any]) -> Finding:
        raise NotImplementedError


_MANIFEST = PluginManifest(
    adapter=_FakeAdapter(),
    package_name="fake-plugin-pkg",
    package_version="0.0.1",
    certificate_identity="https://github.com/acme/fake-plugin/.github/workflows/release.yml@refs/heads/main",
    certificate_oidc_issuer="https://token.actions.githubusercontent.com",
)


class _FakeEntryPoint:
    def __init__(self, name: str, loaded: Any) -> None:
        self.name = name
        self.value = f"fake.module:{name}"
        self._loaded = loaded

    def load(self) -> Any:
        if isinstance(self._loaded, Exception):
            raise self._loaded
        return self._loaded


def _patch_entry_points(monkeypatch: pytest.MonkeyPatch, eps: list[Any]) -> None:
    monkeypatch.setattr(registry, "entry_points", lambda group: eps)


def test_discover_plugins_keys_by_the_adapters_tool_name(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_entry_points(monkeypatch, [_FakeEntryPoint("whatever", _MANIFEST)])
    found = discover_plugins()
    assert list(found) == ["fake-plugin"]
    assert found["fake-plugin"] is _MANIFEST


def test_discover_plugins_accepts_a_zero_arg_callable_too(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_entry_points(monkeypatch, [_FakeEntryPoint("whatever", lambda: _MANIFEST)])
    found = discover_plugins()
    assert found["fake-plugin"] is _MANIFEST


def test_a_broken_plugin_is_skipped_not_fatal_to_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    good = _FakeEntryPoint("good", _MANIFEST)
    broken_import = _FakeEntryPoint("broken", ImportError("missing dependency"))
    wrong_type = _FakeEntryPoint("wrong-type", object())
    _patch_entry_points(monkeypatch, [broken_import, wrong_type, good])
    found = discover_plugins()
    assert list(found) == ["fake-plugin"]


def test_duplicate_plugin_tool_names_keep_the_first_one_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other = PluginManifest(
        adapter=_FakeAdapter(), package_name="other-pkg", package_version="9.9.9",
        certificate_identity="https://github.com/other/x/.github/workflows/release.yml@refs/heads/main",
        certificate_oidc_issuer="https://token.actions.githubusercontent.com",
    )  # fmt: skip
    _patch_entry_points(
        monkeypatch, [_FakeEntryPoint("first", _MANIFEST), _FakeEntryPoint("second", other)]
    )
    found = discover_plugins()
    assert found["fake-plugin"].package_name == "fake-plugin-pkg"


def test_resolve_adapters_always_includes_a_builtin_tool_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_points(monkeypatch, [])
    builtin = {"bandit": _FakeAdapter()}
    out = resolve_adapters(["bandit"], builtin, None, None)
    assert out == {"bandit": builtin["bandit"]}


def test_resolve_adapters_raises_not_found_for_an_unknown_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_points(monkeypatch, [])
    with pytest.raises(PluginNotFoundError):
        resolve_adapters(["nope"], {}, DEFAULT_ORG_ID, object())  # type: ignore[arg-type]


def test_resolve_adapters_requires_both_org_id_and_a_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_points(monkeypatch, [_FakeEntryPoint("x", _MANIFEST)])
    with pytest.raises(PluginNotAllowedError):
        resolve_adapters(["fake-plugin"], {}, None, None)


def test_resolve_adapters_rejects_a_plugin_not_allowlisted_for_this_org(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_entry_points(monkeypatch, [_FakeEntryPoint("x", _MANIFEST)])
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        with pytest.raises(PluginNotAllowedError):
            resolve_adapters(["fake-plugin"], {}, DEFAULT_ORG_ID, s)


def test_resolve_adapters_returns_the_adapter_once_allowed_and_verified(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_entry_points(monkeypatch, [_FakeEntryPoint("x", _MANIFEST)])
    monkeypatch.setattr(registry, "verify_plugin_image", lambda *a, **kw: [])
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_plugin_allowed(s, DEFAULT_ORG_ID, "fake-plugin", enabled=True, allowed_by="t")
        out = resolve_adapters(["fake-plugin"], {}, DEFAULT_ORG_ID, s)
    assert out["fake-plugin"] is _MANIFEST.adapter


def test_resolve_adapters_re_verifies_signature_even_though_already_allowlisted(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The allowlist row records trust in a publisher identity, not a one-time pass -- a plugin
    whose image signature has since gone bad must still be refused, exactly as if it had never been
    allowlisted at all (core.persistence.models.PluginAllowlistRow's own docstring)."""
    _patch_entry_points(monkeypatch, [_FakeEntryPoint("x", _MANIFEST)])
    monkeypatch.setattr(
        registry,
        "verify_plugin_image",
        lambda *a, **kw: (_ for _ in ()).throw(PluginSignatureError("signature drifted")),
    )
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_plugin_allowed(s, DEFAULT_ORG_ID, "fake-plugin", enabled=True, allowed_by="t")
        with pytest.raises(PluginSignatureError):
            resolve_adapters(["fake-plugin"], {}, DEFAULT_ORG_ID, s)
