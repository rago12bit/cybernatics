"""What Bulwark can show about whether a project executes a vulnerability's code (plan §46.3).

For each use of an affected library version in a project, one of:

- **symbols** (Go): Go's vulnerability database names the vulnerable functions, and the project's
  own Go code (`core.reachability.golang`) neither calls nor refers to any of them. The strongest
  evidence Bulwark has, and still not proof: calls made inside other dependencies are not seen.
- **imports** (Python, JavaScript, and Go records without functions): no application source file
  imports the package (or only tests do). Weaker: which functions are vulnerable is not known, and
  another dependency may load the package.
- nothing, with the reason: the code imports or calls it, the version is uncertain, the package is
  malicious (its code runs at install time), the language is not analysed, or the project was
  never scanned by Bulwark.

Only the first two lead to a proposal of `vulnerable_code_not_in_execute_path`; a person decides.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.persistence.models import AdvisoryPackage, CodeUsage, ComponentRow, Library
from core.reachability.golang import GoUsage, symbol_use

KIND_LABEL = {
    "symbols": "Vulnerable functions not called (Go)",
    "imports": "Package not imported by application code",
}
CAVEAT_DEPS = (
    "Code inside other dependencies is not analysed: if another library uses the vulnerable code "
    "on this project's behalf, this claim is wrong."
)
CAVEAT_DYNAMIC = "Calls through reflection, plugins or function values from elsewhere are not seen."
CAVEAT_IMPORT_ONLY = (
    "Import-level only: the advisory does not say which functions are vulnerable, so Bulwark "
    "checked whether the package is imported at all."
)


@dataclass
class Assessment:
    proposable: bool
    kind: str  # symbols | imports | "" (none)
    summary: str
    reachable: bool | None = None  # True when the code is known to use it
    where: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    caveats: list[str] = field(default_factory=list)

    def evidence(self) -> dict[str, Any]:
        return {"kind": self.kind, "label": KIND_LABEL.get(self.kind, ""), "summary": self.summary,
                "details": self.details, "caveats": self.caveats}  # fmt: skip


def record_usage(
    s: Session, *, org_id: str, asset_id: str, scan_id: str, go: GoUsage | None
) -> None:
    """Keep what the project's code uses, from its latest full scan; only Go has any yet."""
    data = {"go": go.to_dict()} if go is not None and go.files else {}
    row = s.scalars(select(CodeUsage).where(CodeUsage.asset_id == asset_id)).first()
    if row is None:
        row = CodeUsage(org_id=org_id, asset_id=asset_id)
        s.add(row)
    row.scan_id, row.data, row.recorded_at = scan_id, data, datetime.now(timezone.utc)
    s.commit()


def go_usage(s: Session, asset_id: str) -> tuple[GoUsage | None, str | None]:
    row = s.scalars(select(CodeUsage).where(CodeUsage.asset_id == asset_id)).first()
    if row is None or "go" not in (row.data or {}):
        return None, row.scan_id if row else None
    return GoUsage.from_dict(row.data["go"]), row.scan_id


def go_imports(
    s: Session, lib: Library, advisory_ids: list[str]
) -> list[tuple[str, list[str]]] | None:
    """The vulnerable packages and functions the records name for this module, or None when no
    record names any."""
    out: dict[str, set[str]] = {}
    for data in s.scalars(
        select(AdvisoryPackage.data).where(
            AdvisoryPackage.advisory_id.in_(advisory_ids), AdvisoryPackage.lib_key == lib.key
        )
    ):
        for imp in (data or {}).get("imports") or []:
            out.setdefault(imp["path"], set()).update(imp.get("symbols") or [])
    if not out:
        return None
    return [(p, sorted(syms)) for p, syms in sorted(out.items())]


def _names(symbols: list[str], limit: int = 4) -> str:
    shown = ", ".join(symbols[:limit])
    return shown + (f" and {len(symbols) - limit} more" if len(symbols) > limit else "")


def assess(
    s: Session,
    *,
    lib: Library,
    version: str,
    advisory_ids: list[str],
    component: ComponentRow | None,
    usage: GoUsage | None,
    certain: bool = True,
    malicious: bool = False,
) -> Assessment:
    if malicious:
        return Assessment(False, "", "A malicious package: its code can run when it is installed")
    if not certain:
        return Assessment(False, "", "The version could not be compared with the advisory")
    if lib.ecosystem == "go":
        return _assess_go(s, lib, advisory_ids, component, usage)
    if lib.ecosystem not in ("pypi", "npm"):
        return Assessment(False, "", f"Code use is not analysed for {lib.ecosystem} packages")
    return _assess_imports(lib, component)


def _assess_imports(lib: Library, component: ComponentRow | None) -> Assessment:
    if component is None or component.reachable is None:
        reason = component.reachable_reason if component else ""
        return Assessment(
            False, "", reason or "Not analysed: the project was not scanned by Bulwark"
        )
    if component.reachable:
        return Assessment(False, "", component.reachable_reason, True, component.reachable_reason)
    return Assessment(
        True, "imports",
        f"{lib.name}: {component.reachable_reason}.",
        False, "",
        {"package": lib.name, "reason": component.reachable_reason,
         "scan_id": component.scan_id},
        [CAVEAT_IMPORT_ONLY, CAVEAT_DEPS],
    )  # fmt: skip


def _assess_go(
    s: Session,
    lib: Library,
    advisory_ids: list[str],
    component: ComponentRow | None,
    usage: GoUsage | None,
) -> Assessment:
    if usage is None or not usage.files:
        return Assessment(False, "", "Not analysed: Bulwark has not scanned this project's Go code")
    imports = go_imports(s, lib, advisory_ids)
    if imports is None:
        out = _assess_imports(lib, component)
        if out.proposable:
            out.details["go_files"] = usage.files
        return out
    packages: list[dict[str, Any]] = []
    for path, symbols in imports:
        use = symbol_use(usage, path, symbols)
        if use.used is None:
            return Assessment(False, "", f"Cannot tell: {use.where}")
        if use.used:
            what = (
                "imports it"
                if use.symbol == "(any)"
                else f"uses {path.rsplit('/', 1)[-1]}.{use.symbol}"
            )
            return Assessment(False, "", f"Application code {what} ({use.where})", True, use.where)
        packages.append({"path": path, "symbols": symbols, "imported_in": usage.imports.get(path)})
    if usage.unparsed:
        return Assessment(False, "", f"Cannot tell: {usage.unparsed} Go files could not be parsed")
    imported = [p for p in packages if p["imported_in"]]
    named = sorted({sym for p in packages for sym in p["symbols"]})
    paths = ", ".join(p["path"] for p in packages)
    if named:
        lead = f"Application code does not call {_names(named)} in {paths}"
    else:
        lead = f"Application code does not import {paths}"
    tail = (
        f"; it imports {len(imported)} of these packages but uses none of the vulnerable functions."
        if imported and named
        else ", and imports none of these packages."
    )
    files = f"{usage.files} Go file{'' if usage.files == 1 else 's'}"
    return Assessment(
        True, "symbols", f"{lead}{tail} Checked {files}.", False, "",
        {"packages": packages, "go_files": usage.files, "selectors": len(usage.selectors)},
        [CAVEAT_DEPS, CAVEAT_DYNAMIC],
    )  # fmt: skip
