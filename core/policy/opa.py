"""Subprocess wrapper around the `opa` binary (plan §20.4).

OPA evaluates already-computed, trusted data (a scan's own findings, an org's own saved policy) --
not the untrusted repository content every other tool in this project scans. There is nothing here
for the sandboxed scanner runner (`core.runner`, gVisor) to protect against, so this runs directly,
the same way `core.risk.score` runs directly rather than through a sandbox: it is application logic
operating on data this platform itself produced, not arbitrary attacker-controlled input.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from core.policy.models import PolicyResult, PolicyTestResult

OPA_TIMEOUT_SECONDS = 30


class OpaNotInstalled(RuntimeError):
    def __init__(self) -> None:
        super().__init__(
            "the 'opa' binary is not installed or not on PATH -- see docs/policy.md for how to "
            "install it (a single static binary from openpolicyagent.org/downloads)"
        )


def _opa_path() -> str:
    path = shutil.which("opa")
    if path is None:
        raise OpaNotInstalled
    return path


def check_syntax(rego: str) -> str | None:
    """`None` if `rego` is syntactically valid; otherwise OPA's own error message. Used before a
    policy is saved (plan §28.6: "Save is disabled until opa test passes") and before it is ever
    handed to `eval_deny`, so a malformed policy fails with a clear message instead of a confusing
    "undefined" result."""
    with tempfile.NamedTemporaryFile("w", suffix=".rego", delete=False) as f:
        f.write(rego)
        path = f.name
    try:
        proc = subprocess.run(
            [_opa_path(), "check", path],
            capture_output=True,
            text=True,
            timeout=OPA_TIMEOUT_SECONDS,
        )
    finally:
        Path(path).unlink(missing_ok=True)
    return None if proc.returncode == 0 else proc.stderr.strip()


def eval_deny(rego: str, package: str, input_data: dict[str, Any]) -> PolicyResult:
    """Runs `data.<package>.deny` against `input_data`. An undefined rule (no policy configured, or
    a package name that doesn't match what's in `rego`) evaluates to no denials, not an error --
    "no policy" is a real, valid state, not a failure (the same "no signal, not a false pass"
    discipline `core.reachability`/`core.taint` already use elsewhere in this project)."""
    syntax_error = check_syntax(rego)
    if syntax_error is not None:
        return PolicyResult(package=package, error=syntax_error)
    with tempfile.NamedTemporaryFile("w", suffix=".rego", delete=False) as f:
        f.write(rego)
        path = f.name
    try:
        proc = subprocess.run(
            [_opa_path(), "eval", "-d", path, "-I", f"data.{package}.deny", "--format", "json"],
            input=json.dumps(input_data),
            capture_output=True,
            text=True,
            timeout=OPA_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return PolicyResult(
            package=package, error=f"policy evaluation timed out after {OPA_TIMEOUT_SECONDS}s"
        )
    finally:
        Path(path).unlink(missing_ok=True)
    if proc.returncode != 0:
        return PolicyResult(package=package, error=proc.stderr.strip() or "opa eval failed")
    try:
        doc = json.loads(proc.stdout) if proc.stdout.strip() else {}
        deny = doc.get("result", [{}])[0].get("expressions", [{}])[0].get("value", [])
    except (ValueError, IndexError, AttributeError, KeyError):
        deny = []
    return PolicyResult(package=package, deny=tuple(str(d) for d in deny))


def run_tests(policy_dir: Path) -> PolicyTestResult:
    """`opa test <dir>` (plan §20.4: "opa test runs the policy tests in CI")."""
    proc = subprocess.run(
        [_opa_path(), "test", str(policy_dir), "--format", "json"],
        capture_output=True,
        text=True,
        timeout=OPA_TIMEOUT_SECONDS,
    )
    if proc.returncode not in (
        0,
        2,
    ):  # 0: all pass, 2: at least one failed -- both are real results
        return PolicyTestResult(
            passed=0, failed=1, failures=(proc.stderr.strip() or "opa test failed",)
        )
    try:
        results = json.loads(proc.stdout) if proc.stdout.strip() else []
    except ValueError:
        return PolicyTestResult(
            passed=0, failed=1, failures=("opa test produced no readable output",)
        )
    failed = [r for r in results if r.get("fail")]
    passed = [r for r in results if not r.get("fail") and "error" not in r]
    failures = tuple(f"{r.get('package', '?')}.{r.get('name', '?')}" for r in failed)
    return PolicyTestResult(passed=len(passed), failed=len(failed), failures=failures)


__all__ = ["OpaNotInstalled", "check_syntax", "eval_deny", "run_tests"]
