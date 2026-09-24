"""Scan pipeline: detect -> select tools -> run in sandboxes (parallel) -> parse -> redact."""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.adapters import RepoContext, ToolAdapter
from core.adapters.bandit import BanditAdapter
from core.adapters.gitleaks import GitleaksAdapter
from core.adapters.osv_scanner import OsvScannerAdapter
from core.adapters.semgrep import SemgrepAdapter
from core.adapters.trivy import TrivyAdapter
from core.models import Finding, finding_from_dict
from core.redact import redact_near_secrets
from core.runner import RunnerError, run_tool

ADAPTERS: dict[str, ToolAdapter] = {
    a.spec.name: a
    for a in (
        BanditAdapter(),
        SemgrepAdapter(),
        GitleaksAdapter(),
        TrivyAdapter(),
        OsvScannerAdapter(),
    )
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
    "requirements.txt", "go.mod", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock",
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
class ToolOutcome:
    """Result of one tool run. A failed tool is data, never an exception (partial results)."""

    tool: str
    status: str  # ok | timeout | error | skipped
    findings: list[Finding] = field(default_factory=list)
    exit_code: int | None = None
    duration_seconds: float = 0.0
    error: str | None = None
    raw: bytes = b""  # not serialized; stored as an artifact only after secret-safety checks

    def status_block(self) -> dict[str, Any]:
        block: dict[str, Any] = {
            "status": self.status,
            "findings": len(self.findings),
            "exit_code": self.exit_code,
            "duration_seconds": round(self.duration_seconds, 2),
        }
        if self.error:
            block["error"] = self.error
        return block

    def to_dict(self) -> dict[str, Any]:
        return {**self.status_block(), "tool": self.tool,
                "finding_dicts": [f.to_dict() for f in self.findings]}  # fmt: skip

    @staticmethod
    def from_dict(d: dict[str, Any]) -> ToolOutcome:
        return ToolOutcome(
            tool=d["tool"],
            status=d["status"],
            findings=[finding_from_dict(f) for f in d["finding_dicts"]],
            exit_code=d["exit_code"],
            duration_seconds=d["duration_seconds"],
            error=d.get("error"),
        )


def execute_tool(name: str, target: Path) -> ToolOutcome:
    """The unit of work: run one tool in its sandbox and parse. Used by threads and Celery."""
    adapter = ADAPTERS[name]
    start = time.monotonic()
    try:
        run = run_tool(adapter, target, detect_context(target))
    except RunnerError as exc:
        return ToolOutcome(name, "error", error=str(exc), duration_seconds=time.monotonic() - start)
    findings = adapter.parse(run.raw) if run.raw else []
    # No output = failure; output with zero findings = clean pass.
    error = None if run.status == "ok" else (run.stderr.strip() or run.status)[-500:]
    return ToolOutcome(
        name, run.status, findings, run.exit_code, time.monotonic() - start, error, run.raw
    )


Executor = Callable[[list[str], Path], list[ToolOutcome]]


def threaded_executor(tools: list[str], target: Path) -> list[ToolOutcome]:
    with ThreadPoolExecutor(max_workers=max(len(tools), 1)) as pool:
        futures = [pool.submit(execute_tool, t, target) for t in tools]
    outcomes: list[ToolOutcome] = []
    for tool, fut in zip(tools, futures, strict=True):
        try:
            outcomes.append(fut.result())
        except Exception as exc:  # noqa: BLE001 - one tool dying must not fail the scan
            outcomes.append(ToolOutcome(tool, "error", error=f"{type(exc).__name__}: {exc}"))
    return outcomes


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    tool_status: dict[str, dict[str, Any]] = field(default_factory=dict)


def scan(target: Path, tools: list[str], executor: Executor = threaded_executor) -> ScanResult:
    unknown = [t for t in tools if t not in ADAPTERS]
    if unknown:
        raise ValueError(f"unknown tool(s): {', '.join(unknown)}")
    ctx = detect_context(target)
    result = ScanResult()
    runnable: list[str] = []
    for name in tools:
        if ADAPTERS[name].applies_to(ctx):
            runnable.append(name)
        else:
            result.tool_status[name] = {"status": "skipped", "reason": "no relevant files"}
    outcomes = {o.tool: o for o in executor(runnable, target)} if runnable else {}
    for name in runnable:  # stable, request-ordered output
        o = outcomes.get(name) or ToolOutcome(name, "error", error="executor returned no result")
        result.tool_status[name] = o.status_block()
        result.findings.extend(o.findings)
    result.findings = redact_near_secrets(result.findings)
    return result
