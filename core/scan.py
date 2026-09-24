"""Scan pipeline: detect -> select tools -> run in sandbox -> parse -> report."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from core.adapters import RepoContext, ToolAdapter
from core.adapters.bandit import BanditAdapter
from core.adapters.gitleaks import GitleaksAdapter
from core.adapters.semgrep import SemgrepAdapter
from core.models import Finding
from core.redact import redact_near_secrets
from core.runner import run_tool

ADAPTERS: dict[str, ToolAdapter] = {
    a.spec.name: a for a in (BanditAdapter(), SemgrepAdapter(), GitleaksAdapter())
}

_EXT_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".go": "go",
    ".java": "java",
}
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}


_LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "requirements.txt", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock",
}  # fmt: skip
_IAC_SUFFIXES = {".tf", ".tfvars"}


def detect_context(root: Path) -> RepoContext:
    langs: set[str] = set()
    lockfiles: list[str] = []
    has_dockerfile = has_iac = False
    for p in root.rglob("*"):
        rel = p.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts) or not p.is_file():
            continue
        if p.suffix in _EXT_LANG:
            langs.add(_EXT_LANG[p.suffix])
        if p.name in _LOCKFILES:
            lockfiles.append(str(rel))
        if p.name == "Dockerfile" or p.name.startswith("Dockerfile."):
            has_dockerfile = True
        if p.suffix in _IAC_SUFFIXES:
            has_iac = True
    return RepoContext(
        root=root,
        languages=frozenset(langs),
        has_dockerfile=has_dockerfile,
        has_iac=has_iac,
        lockfiles=tuple(sorted(lockfiles)),
    )


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    tool_status: dict[str, dict[str, object]] = field(default_factory=dict)


def scan(target: Path, tools: list[str]) -> ScanResult:
    unknown = [t for t in tools if t not in ADAPTERS]
    if unknown:
        raise ValueError(f"unknown tool(s): {', '.join(unknown)}")
    ctx = detect_context(target)
    result = ScanResult()
    for name in tools:
        adapter = ADAPTERS[name]
        if not adapter.applies_to(ctx):
            result.tool_status[name] = {"status": "skipped", "reason": "no relevant files"}
            continue
        run = run_tool(adapter, target)
        found = adapter.parse(run.raw) if run.raw else []
        result.findings.extend(found)
        result.tool_status[name] = {
            "status": run.status,
            "findings": len(found),
            "exit_code": run.exit_code,
        }
    result.findings = redact_near_secrets(result.findings)
    return result
