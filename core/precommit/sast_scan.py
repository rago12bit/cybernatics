"""Fast, native Python SAST for the pre-commit hook (Week 51 task 4, plan §23).

`bulwark scan`'s own Python SAST is Bandit, run in Docker (core/adapters/bandit.py) -- far too slow
to run on every commit. This module checks staged Python files in-process with the stdlib `ast`
module: no subprocess, no container, and (because it only has to parse, not execute, the file)
fast even on a large diff. It covers a short list of high-confidence, low-noise checks, each one a
pattern Bandit itself flags, picked because they are almost never intentional. It is a deliberately
narrow complement to `bulwark scan --tools bandit`, not a replacement for it: no taint analysis, no
cross-function reasoning, no CWE coverage beyond these eight checks.

Only syntactically valid Python is checked -- a file that doesn't parse is skipped here (CI's own
`bulwark scan` and the language's own tooling already catch a syntax error long before this hook
would matter).
"""

from __future__ import annotations

import ast
from collections.abc import Callable

from core.adapters.helpers import make_finding
from core.models import Category, Finding

_SHELL_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen",
}  # fmt: skip
_PICKLE_FUNCS = {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"}
_OS_EXEC_FUNCS = {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"}
_WEAK_HASHES = {"hashlib.md5", "hashlib.sha1"}


def _dotted(node: ast.expr) -> str:
    """Best-effort "a.b.c" for a Call's func, or "" when it isn't a plain attribute/name chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_const(node: ast.expr | None, value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def _check_eval_exec(call: ast.Call, dotted: str) -> str | None:
    if dotted in ("eval", "exec"):
        return f"Call to {dotted}() on a value that may not be a fixed, trusted literal"
    return None


def _check_shell_exec(call: ast.Call, dotted: str) -> str | None:
    if dotted in _OS_EXEC_FUNCS:
        return f"{dotted}() runs a shell command built from its argument"
    if dotted in _SHELL_FUNCS and _is_const(_kwarg(call, "shell"), True):
        return f"{dotted}(..., shell=True) runs its argument through a shell"
    return None


def _check_pickle(call: ast.Call, dotted: str) -> str | None:
    if dotted in _PICKLE_FUNCS:
        return f"{dotted}() can execute arbitrary code when given untrusted input"
    return None


def _check_yaml_load(call: ast.Call, dotted: str) -> str | None:
    if dotted != "yaml.load":
        return None
    loader = _kwarg(call, "Loader")
    if loader is not None and _dotted(loader) in ("yaml.SafeLoader", "yaml.CSafeLoader"):
        return None
    return "yaml.load() without Loader=yaml.SafeLoader can construct arbitrary Python objects"


def _check_weak_hash(call: ast.Call, dotted: str) -> str | None:
    if dotted in _WEAK_HASHES:
        return f"{dotted}() is cryptographically broken; unsuitable for passwords or signatures"
    return None


def _check_mktemp(call: ast.Call, dotted: str) -> str | None:
    if dotted == "tempfile.mktemp":
        return (
            "tempfile.mktemp() names a file without creating it: a race condition "
            "(use NamedTemporaryFile)"
        )
    return None


def _check_tls_verify_false(call: ast.Call, dotted: str) -> str | None:
    if dotted == "ssl._create_unverified_context":
        return "ssl._create_unverified_context() disables TLS certificate verification entirely"
    if _is_const(_kwarg(call, "verify"), False):
        return f"{dotted or 'this call'}(..., verify=False) disables TLS certificate verification"
    return None


# (rule_id, native severity, cwe, checker) -- checked in order, first match per Call wins.
_RULES: tuple[tuple[str, str, str, Callable[[ast.Call, str], str | None]], ...] = (
    ("PCA001", "HIGH", "CWE-95", _check_eval_exec),
    ("PCA002", "HIGH", "CWE-78", _check_shell_exec),
    ("PCA003", "HIGH", "CWE-295", _check_tls_verify_false),
    ("PCA004", "MEDIUM", "CWE-502", _check_pickle),
    ("PCA005", "MEDIUM", "CWE-502", _check_yaml_load),
    ("PCA006", "MEDIUM", "CWE-377", _check_mktemp),
    ("PCA007", "LOW", "CWE-327", _check_weak_hash),
)


def scan_python_sast(path: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError:
        return []
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted(node.func)
        for rule_id, native, cwe, check in _RULES:
            message = check(node, dotted)
            if message is None:
                continue
            out.append(
                make_finding(
                    "precommit-sast",
                    Category.SAST,
                    rule=rule_id,
                    title=message,
                    path=path,
                    start=node.lineno,
                    end=getattr(node, "end_lineno", node.lineno) or node.lineno,
                    snippet=ast.unparse(node)[:200],
                    native=native,
                    description=message,
                    confidence=0.7,
                    cwe=[cwe],
                )
            )
            break  # one finding per call site is enough; don't pile on the same line
    return out
