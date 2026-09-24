"""Scan pipeline: detect -> select tools -> run in sandbox -> parse -> report."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from core.adapters import RepoContext, ToolAdapter
from core.adapters.bandit import BanditAdapter
from core.models import Finding
from core.runner import run_tool

ADAPTERS: dict[str, ToolAdapter] = {a.spec.name: a for a in (BanditAdapter(),)}

_EXT_LANG = {".py": "python", ".js": "javascript", ".ts": "javascript", ".go": "go"}
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}


def detect_context(root: Path) -> RepoContext:
    langs: set[str] = set()
    for p in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.is_file() and p.suffix in _EXT_LANG:
            langs.add(_EXT_LANG[p.suffix])
    return RepoContext(root=root, languages=frozenset(langs))


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
    return result
