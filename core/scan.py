"""Scan pipeline: detect -> select tools -> run in sandboxes (parallel) -> parse -> redact."""

from __future__ import annotations

import dataclasses
import logging
import os
import shutil
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.adapters import RepoContext, ToolAdapter
from core.adapters.bandit import BanditAdapter
from core.adapters.checkov import CheckovAdapter
from core.adapters.dockle import IMAGE_ARCHIVE, DockleAdapter
from core.adapters.gitleaks import GitleaksAdapter
from core.adapters.gosec import GosecAdapter
from core.adapters.grype import GrypeAdapter
from core.adapters.opengrep import OpengrepAdapter
from core.adapters.osv_scanner import OsvScannerAdapter
from core.adapters.semgrep import SemgrepAdapter
from core.adapters.trivy import TrivyAdapter
from core.cache import CacheKey, ResultCache, hash_file, hash_files
from core.config import scratch_dir
from core.correlation import CorrelationStats, correlate
from core.ignore import IGNORE_FILE, IgnoreRules, apply_ignore
from core.models import Finding, finding_from_dict
from core.observability import bind_tool, in_context, mark_error, set_attributes, span
from core.observability import metrics as obs
from core.postprocess import finalize
from core.reachability import analyze_or_none
from core.runner import RunnerError, run_tool
from core.sandbox.docker_runtime import image_tag
from core.sbom.syft import SyftAdapter
from core.taint import analyze_or_none as taint_analyze_or_none

ADAPTERS: dict[str, ToolAdapter] = {
    a.spec.name: a
    for a in (
        BanditAdapter(),
        SemgrepAdapter(),
        GitleaksAdapter(),
        TrivyAdapter(),
        OsvScannerAdapter(),
        # Tier 2: selectable with --tools, not run by default (heavier images, overlap with tier 1).
        GrypeAdapter(),
        CheckovAdapter(),
        GosecAdapter(),
        DockleAdapter(),
        # SBOM + supply-chain risk (plan §20.5): opting into "syft" also gets typosquat detection
        # and OpenSSF Scorecard for direct dependencies (`core.pipeline`), not just the raw SBOM
        # artifact -- one toggle for the whole feature area, not three.
        SyftAdapter(),
        # Hosted mode's SAST tool (ADR-0038, Week 53): not in DEFAULT_TOOLS below -- self-host
        # deployments keep using Semgrep, since nothing about their own use needs Opengrep's
        # narrower, originally-authored ruleset. Selected instead of Semgrep only when
        # `Settings.hosted_mode` is set (api/main.py's `_tools`), which also then refuses "semgrep".
        OpengrepAdapter(),
    )
}
DEFAULT_TOOLS: tuple[str, ...] = ("bandit", "semgrep", "gitleaks", "trivy", "osv-scanner")
# Hosted mode's equivalent (ADR-0038): Opengrep instead of Semgrep, so a hosted deployment's own
# default scan never runs a tool licensed for internal use only.
HOSTED_DEFAULT_TOOLS: tuple[str, ...] = ("bandit", "opengrep", "gitleaks", "trivy", "osv-scanner")

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
    "requirements.txt", "pom.xml", "go.mod", "go.sum", "Cargo.lock", "Gemfile.lock",
    "composer.lock",
}  # fmt: skip
_IAC_SUFFIXES = {".tf", ".tfvars"}

log = logging.getLogger(__name__)


def detect_context(root: Path) -> RepoContext:
    langs: set[str] = set()
    lockfiles: list[str] = []
    has_dockerfile = has_iac = has_image = False
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
        if rel.as_posix() == IMAGE_ARCHIVE:
            has_image = True
    return RepoContext(
        root=root,
        languages=frozenset(langs),
        has_dockerfile=has_dockerfile,
        has_iac=has_iac,
        lockfiles=tuple(sorted(lockfiles)),
        has_image_archive=has_image,
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
    warnings: list[str] = field(default_factory=list)  # ok, but possibly incomplete

    def status_block(self) -> dict[str, Any]:
        block: dict[str, Any] = {
            "status": self.status,
            "findings": len(self.findings),
            "exit_code": self.exit_code,
            "duration_seconds": round(self.duration_seconds, 2),
        }
        if self.error:
            block["error"] = self.error
        if self.warnings:
            block["warnings"] = self.warnings
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
            warnings=list(d.get("warnings", [])),
        )


def execute_tool(
    name: str,
    target: Path,
    ctx: RepoContext | None = None,
    adapters: Mapping[str, ToolAdapter] | None = None,
) -> ToolOutcome:
    """The unit of work: run one tool in its sandbox and parse. Used by threads and Celery.

    `ctx`: pass the *target repo's* context, not `target`'s own, when `target` is a subset
    directory standing in for it (`core.cache`'s cache-miss subset) -- otherwise a tool whose
    command depends on context (Semgrep's rule selection) would see only the subset's languages.

    `adapters`: the built-in `ADAPTERS` registry by default. `core.pipeline` passes its own
    per-scan, org-resolved table instead (`core.plugins.registry.resolve_adapters`) so a plugin
    tool's adapter instance is used here without ever mutating the shared, process-global registry
    (which concurrent scans for different organizations share and must not see each other's
    plugins through).
    """
    adapters = adapters if adapters is not None else ADAPTERS
    with bind_tool(name), span(f"tool.{name}", tool=name, image=adapters[name].spec.image) as sp:
        outcome = _execute_tool(name, target, ctx, adapters)
        set_attributes(sp, status=outcome.status, findings=len(outcome.findings),
                       exit_code=outcome.exit_code)  # fmt: skip
        if outcome.status != "ok":
            mark_error(sp, outcome.error or outcome.status)
        obs.observe_tool(name, outcome.status, outcome.duration_seconds)
        log.info(
            "tool finished",
            extra={"status": outcome.status, "findings": len(outcome.findings),
                   "duration_s": round(outcome.duration_seconds or 0.0, 2)},
        )  # fmt: skip
        return outcome


def _execute_tool(
    name: str,
    target: Path,
    ctx: RepoContext | None = None,
    adapters: Mapping[str, ToolAdapter] | None = None,
) -> ToolOutcome:
    adapter = (adapters if adapters is not None else ADAPTERS)[name]
    start = time.monotonic()
    try:
        run = run_tool(adapter, target, ctx if ctx is not None else detect_context(target))
    except RunnerError as exc:
        return ToolOutcome(name, "error", error=str(exc), duration_seconds=time.monotonic() - start)
    findings = adapter.parse(run.raw) if run.raw else []
    # No output = failure; output with zero findings = clean pass.
    error = None if run.status == "ok" else (run.stderr.strip() or run.status)[-500:]
    warnings = adapter.warnings(run.raw) if run.raw and run.status == "ok" else []
    return ToolOutcome(
        name,
        run.status,
        findings,
        run.exit_code,
        time.monotonic() - start,
        error,
        run.raw,
        warnings,
    )


Executor = Callable[[list[str], Path], list[ToolOutcome]]


def threaded_executor(tools: list[str], target: Path) -> list[ToolOutcome]:
    with ThreadPoolExecutor(max_workers=max(len(tools), 1)) as pool:
        futures = [pool.submit(in_context(execute_tool), t, target) for t in tools]
    outcomes: list[ToolOutcome] = []
    for tool, fut in zip(tools, futures, strict=True):
        try:
            outcomes.append(fut.result())
        except Exception as exc:  # noqa: BLE001 - one tool dying must not fail the scan
            outcomes.append(ToolOutcome(tool, "error", error=f"{type(exc).__name__}: {exc}"))
    return outcomes


# ---- Content-addressed result cache (plan §20.1) --------------------------------------------
#
# File-local tools: cached per file, so a change to one file in a 5,000-file repo costs one file's
# worth of scanning, not the whole tree's. Repo-wide (SCA) tools: cached as a whole, keyed on the
# files that actually drive their output -- there's no per-file result to reuse from a lockfile
# scan or an IaC misconfiguration pass.
CACHEABLE_FILE_LOCAL: frozenset[str] = frozenset({"bandit", "semgrep", "gitleaks"})
CACHEABLE_REPO_WIDE: frozenset[str] = frozenset({"trivy", "osv-scanner"})


def _tool_version(name: str) -> str:
    return image_tag(ADAPTERS[name].spec.image)


def _relevant_files(name: str, target: Path, ctx: RepoContext) -> list[Path]:
    """Files whose content actually changes what `name` reports -- what a file-local tool's cache
    is keyed on, one entry per file. Mirrors `detect_context`'s own walk and skip-dirs so a file
    this tool would never look at doesn't generate a pointless cache entry."""
    if name == "gitleaks":
        wanted: frozenset[str] | None = None  # secrets can live in any file
    elif name == "bandit":
        wanted = frozenset({".py"})
    elif name == "semgrep":
        wanted = frozenset(ext for ext, lang in _EXT_LANG.items() if lang in ctx.languages)
    else:
        return []
    out: list[Path] = []
    for p in target.rglob("*"):
        rel = p.relative_to(target)
        if any(part in _SKIP_DIRS for part in rel.parts) or not p.is_file():
            continue
        if wanted is None or p.suffix in wanted:
            out.append(p)
    return out


def _repo_wide_files(name: str, target: Path, ctx: RepoContext) -> list[Path]:
    """Files a repo-wide tool's *whole* cached result is keyed on. OSV-Scanner only ever looks at
    lockfiles (its own `applies_to`); Trivy also reports on Dockerfile and IaC misconfigurations
    (its `applies_to` includes those too), so its key must cover them as well -- keying it on
    lockfiles alone would silently serve a stale result after an unrelated Dockerfile edit."""
    paths = [target / lf for lf in ctx.lockfiles]
    if name == "trivy":
        for p in target.rglob("*"):
            rel = p.relative_to(target)
            if any(part in _SKIP_DIRS for part in rel.parts) or not p.is_file():
                continue
            is_dockerfile = p.name == "Dockerfile" or p.name.startswith("Dockerfile.")
            if is_dockerfile or p.suffix in _IAC_SUFFIXES:
                paths.append(p)
    return paths


@contextmanager
def _subset_dir(target: Path, files: list[Path]) -> Iterator[Path]:
    """A throwaway directory holding only `files`, at their original paths relative to `target`.

    Copied, not symlinked: the sandbox mounts this directory into a container that has no view of
    the real `target` at all, so a symlink pointing back out to it would just be a dangling path
    from inside the container."""
    with tempfile.TemporaryDirectory(prefix="bulwark-subset-", dir=scratch_dir()) as tmp:
        tmp_path = Path(tmp)
        for f in files:
            dest = tmp_path / f.relative_to(target)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
            os.chmod(dest, 0o644)
        # TemporaryDirectory is 0700 and owned by this process's user; the scanner runs as uid
        # 10001, so on Linux it saw "/target is not readable" and every cache-miss run of semgrep
        # and gitleaks in the GitHub Action failed. Readable like prepare_workspace's output.
        for d in (tmp_path, *(p for p in tmp_path.rglob("*") if p.is_dir())):
            os.chmod(d, 0o755)
        yield tmp_path


def _moved_to(findings: list[Finding], rel: str) -> list[Finding]:
    """A file-local entry is keyed by content alone, and the same bytes can sit at another path: a
    copy, a renamed or moved file, every empty __init__.py. Its findings carry the path of the file
    that produced them; serve them at the file that matched now. Before this, a second copy of a
    file reported its findings again at the first one's path -- duplicates that regrouped that
    file's real findings and changed their fingerprints, so a PR gate saw them as new."""
    out: list[Finding] = []
    for f in findings:
        old = f.location.path
        if old == rel:
            out.append(f)
            continue
        out.append(
            dataclasses.replace(
                f,
                id=f.id.replace(old, rel),
                location=dataclasses.replace(f.location, path=rel),
            )
        )
    return out


def _cached_file_local(
    name: str, target: Path, ctx: RepoContext, cache: ResultCache
) -> ToolOutcome:
    files = _relevant_files(name, target, ctx)
    version, ruleset = _tool_version(name), ADAPTERS[name].ruleset_id(ctx)
    hit_findings: list[Finding] = []
    misses: list[Path] = []
    for f in files:
        cached = cache.get(CacheKey(name, version, ruleset, hash_file(f)))
        if cached is None:
            misses.append(f)
        else:
            hit_findings.extend(_moved_to(cached, f.relative_to(target).as_posix()))
    if not misses:
        return ToolOutcome(name, "ok", hit_findings, 0, 0.0)
    with _subset_dir(target, misses) as subset:
        outcome = execute_tool(name, subset, ctx)
    if outcome.status != "ok":
        # A cache is a performance optimization, not a new correctness path: on failure, behave
        # exactly as an uncached run would rather than inventing partial-success semantics.
        return outcome
    by_path: dict[str, list[Finding]] = {}
    for fnd in outcome.findings:
        by_path.setdefault(fnd.location.path, []).append(fnd)
    for f in misses:
        rel = f.relative_to(target).as_posix()
        cache.set(CacheKey(name, version, ruleset, hash_file(f)), by_path.get(rel, []))
    return ToolOutcome(
        name, "ok", hit_findings + outcome.findings, outcome.exit_code,
        outcome.duration_seconds, None, outcome.raw, outcome.warnings,
    )  # fmt: skip


def _cached_repo_wide(name: str, target: Path, ctx: RepoContext, cache: ResultCache) -> ToolOutcome:
    files = _repo_wide_files(name, target, ctx)
    if not files:  # nothing to key on (shouldn't happen: applies_to() already gated this tool in)
        return execute_tool(name, target, ctx)
    key = CacheKey(
        name, _tool_version(name), ADAPTERS[name].ruleset_id(ctx), hash_files(files, target)
    )
    cached = cache.get(key)
    if cached is not None:
        return ToolOutcome(name, "ok", cached, 0, 0.0)
    outcome = execute_tool(name, target, ctx)
    if outcome.status == "ok":
        cache.set(key, outcome.findings)
    return outcome


def cached_outcomes(
    tools: list[str], target: Path, ctx: RepoContext, cache: ResultCache
) -> dict[str, ToolOutcome]:
    """Cache-aware counterpart to running `tools` directly (plan §20.1). Tier-2 tools (Grype,
    Checkov, gosec, Dockle) aren't cached this week -- they're opt-in, not part of any default
    scan, and none of them is on the pull-request-speed critical path yet."""
    out: dict[str, ToolOutcome] = {}
    for name in tools:
        if name in CACHEABLE_FILE_LOCAL:
            out[name] = _cached_file_local(name, target, ctx, cache)
        elif name in CACHEABLE_REPO_WIDE:
            out[name] = _cached_repo_wide(name, target, ctx, cache)
        else:
            out[name] = execute_tool(name, target, ctx)
    return out


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    stats: CorrelationStats = field(default_factory=lambda: CorrelationStats(0, 0))
    tool_status: dict[str, dict[str, Any]] = field(default_factory=dict)
    ignored: int = 0  # findings dropped by .bulwarkignore, reported so ignoring is never silent


def scan(
    target: Path,
    tools: list[str],
    executor: Executor = threaded_executor,
    ignore: IgnoreRules | None = None,
    cache: ResultCache | None = None,
) -> ScanResult:
    """`cache` (plan §20.1): opt-in content-addressed result cache. Tools other than
    `CACHEABLE_FILE_LOCAL`/`CACHEABLE_REPO_WIDE` are unaffected either way. Ignored when `executor`
    isn't the default (e.g. `--distributed`'s Celery executor) -- wiring the cache through workers
    that each own their own copy of the target is future work, not something this week's CLI/Action
    speed target needs; the CLI rejects combining the two rather than silently dropping one."""
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
    if cache is not None and runnable:
        outcomes = cached_outcomes(runnable, target, ctx, cache)
    else:
        outcomes = {o.tool: o for o in executor(runnable, target)} if runnable else {}
    for name in runnable:  # stable, request-ordered output
        o = outcomes.get(name) or ToolOutcome(name, "error", error="executor returned no result")
        result.tool_status[name] = o.status_block()
        result.findings.extend(o.findings)
    # Correlate BEFORE redacting: redaction placeholders look identical and would over-merge.
    correlated, result.stats = correlate(result.findings)
    rules = ignore if ignore is not None else IgnoreRules.load(target / IGNORE_FILE)
    correlated, result.ignored = apply_ignore(correlated, rules)
    result.findings = finalize(
        correlated,
        reach=analyze_or_none(target),
        taint=taint_analyze_or_none(target),
        root=target,
    )
    return result
