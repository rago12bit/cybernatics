"""Rule conditions in Rego, evaluated by the OPA the policy gate already uses (plan §45, §20.4).

A condition is the body of one Rego rule: lines that must all hold, written against `input`
(`input.issue`, `input.project`, `input.event`). It is wrapped in a fixed module, and many inputs
are checked in one `opa eval`: `hits` is the set of positions in `input.items` whose item matches.
One process for a whole batch keeps a scan's five hundred new Issues to one evaluation, not five
hundred.

Rego here is written by an Admin but still treated as code that must not reach anything:
- `http.send`, `net.lookup_ip_addr` and `opa.runtime` are removed from OPA's capabilities, and the
  network allow-list is empty, so a condition can neither call out nor read the environment. A
  condition that uses them fails to compile, with OPA's own message.
- `opa` runs with an empty environment, so even a builtin that slipped through would find nothing.
- Each evaluation has a time limit; a condition is at most 4,000 characters and may not declare its
  own package or imports.
"""

from __future__ import annotations

import functools
import json
import os
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from core.policy.opa import _opa_path

PACKAGE = "bulwark.rule"
TIMEOUT_SECONDS = 10
MAX_CONDITION = 4000
DENIED_BUILTINS = frozenset({"http.send", "net.lookup_ip_addr", "opa.runtime"})


class ConditionError(ValueError):
    """The condition does not compile, or could not be evaluated."""

    field = "condition"


def module(condition: str) -> str:
    body = "\n".join(f"  {line}".rstrip() for line in condition.strip("\n").splitlines())
    body = body if body.strip() else ""
    return (
        f"package {PACKAGE}\n\nimport rego.v1\n\ndefault match := false\n\n"
        f"match if {{\n{body or '  true'}\n}}\n\n"
        "hits contains i if {\n  some i, item in input.items\n  match with input as item\n}\n"
    )


def _env() -> dict[str, str]:
    return {}


@functools.cache
def capabilities_file() -> str:
    """OPA's own capabilities for this binary, minus the denied builtins, written once per
    process to a private temporary file."""
    proc = subprocess.run(
        [_opa_path(), "capabilities", "--current"],
        capture_output=True, text=True, timeout=TIMEOUT_SECONDS, env=_env(),
    )  # fmt: skip
    if proc.returncode != 0:
        raise ConditionError(proc.stderr.strip() or "could not read OPA's capabilities")
    caps = json.loads(proc.stdout)
    caps["builtins"] = [b for b in caps["builtins"] if b.get("name") not in DENIED_BUILTINS]
    caps["allow_net"] = []
    fd, path = tempfile.mkstemp(prefix="bulwark-rego-caps-", suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(caps, f)
    return path


def _validate_text(condition: str) -> None:
    if len(condition) > MAX_CONDITION:
        raise ConditionError(f"The condition is at most {MAX_CONDITION} characters.")
    for line in condition.splitlines():
        word = line.strip().split(" ", 1)[0]
        if word in ("package", "import"):
            raise ConditionError(f"Write only the condition's lines; '{word}' is added for you.")


def _with_module(condition: str) -> tuple[str, str]:
    _validate_text(condition)
    fd, path = tempfile.mkstemp(prefix="bulwark-rule-", suffix=".rego")
    with os.fdopen(fd, "w") as f:
        f.write(module(condition))
    return path, capabilities_file()


def _clean(message: str, path: str) -> str:
    """OPA's message, with the temporary file's name replaced and line numbers made the
    condition's own (the wrapper puts seven lines before it)."""
    out = []
    for line in message.replace(path, "condition").splitlines():
        head, sep, rest = line.partition("condition:")
        if sep:
            number, colon, tail = rest.partition(":")
            if number.isdigit() and colon:
                line = f"{head}line {max(1, int(number) - 7)}:{tail}"
        out.append(line)
    return "\n".join(out).strip()


def check(condition: str) -> None:
    """Raises ConditionError with OPA's message if the condition does not compile."""
    path, caps = _with_module(condition)
    try:
        proc = subprocess.run(
            [_opa_path(), "check", "--capabilities", caps, path],
            capture_output=True, text=True, timeout=TIMEOUT_SECONDS, env=_env(),
        )  # fmt: skip
    except subprocess.TimeoutExpired as exc:
        raise ConditionError("Checking the condition took too long.") from exc
    finally:
        Path(path).unlink(missing_ok=True)
    if proc.returncode != 0:
        raise ConditionError(_clean(proc.stderr or proc.stdout, path) or "It does not compile.")


def matches(condition: str, items: Sequence[dict[str, Any]]) -> set[int]:
    """Positions in `items` whose document satisfies the condition, in one evaluation."""
    if not items:
        return set()
    path, caps = _with_module(condition)
    try:
        proc = subprocess.run(
            [_opa_path(), "eval", "--capabilities", caps, "-d", path, "-I", "--format", "json",
             f"data.{PACKAGE}.hits"],
            input=json.dumps({"items": list(items)}, default=str),
            capture_output=True, text=True, timeout=TIMEOUT_SECONDS, env=_env(),
        )  # fmt: skip
    except subprocess.TimeoutExpired as exc:
        raise ConditionError(
            f"Evaluating the condition took longer than {TIMEOUT_SECONDS} seconds."
        ) from exc
    finally:
        Path(path).unlink(missing_ok=True)
    if proc.returncode != 0:
        raise ConditionError(_clean(proc.stderr or proc.stdout, path) or "opa eval failed")
    try:
        doc = json.loads(proc.stdout)
        value = doc["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError):
        return set()
    return {int(i) for i in value if isinstance(i, int) and 0 <= i < len(items)}


__all__ = ["ConditionError", "MAX_CONDITION", "check", "matches", "module"]
