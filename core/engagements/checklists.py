"""The OWASP checklists an assessment can follow (plan §43.1), shipped as data in `checklists/`.

- `wstg-4.2`: the Web Security Testing Guide 4.2's 114 tests (OWASP/wstg `checklists/checklist.json`
  at tag v4.2).
- `asvs-4.0.3-l1`, `-l2`, `-l3`: the Application Security Verification Standard 4.0.3's
  requirements up to that level (128, 259 and 278), from OWASP/ASVS at tag v4.0.3.

Both are © OWASP Foundation, CC BY-SA 4.0 (THIRD_PARTY_LICENSES.md). The files keep each item's
id, its group, its title, and for ASVS its level and CWE; nothing is reworded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path

_DIR = Path(__file__).parent / "checklists"
ATTRIBUTION = "OWASP Foundation, CC BY-SA 4.0"


@dataclass(frozen=True)
class Item:
    id: str
    group: str
    title: str
    level: int | None = None
    cwe: str | None = None
    reference: str | None = None


@dataclass(frozen=True)
class Checklist:
    id: str
    name: str
    source: str
    items: tuple[Item, ...]

    def has(self, item_id: str) -> bool:
        return any(i.id == item_id for i in self.items)


@cache
def _load(file_id: str) -> dict:  # type: ignore[type-arg]
    data: dict = json.loads((_DIR / f"{file_id}.json").read_text(encoding="utf-8"))  # type: ignore[type-arg]
    return data


def _build(file_id: str, *, max_level: int | None = None, suffix: str = "") -> Checklist:
    raw = _load(file_id)
    items = tuple(
        Item(i["id"], i["group"], i["title"], i.get("level"), i.get("cwe"), i.get("reference"))
        for i in raw["items"]
        if max_level is None or (i.get("level") or 0) <= max_level
    )
    return Checklist(f"{raw['id']}{suffix}", f"{raw['name']}{suffix.upper().replace('-', ' ')}",
                     raw["source"], items)  # fmt: skip


@cache
def catalogue() -> dict[str, Checklist]:
    out = {"wstg-4.2": _build("wstg-4.2")}
    for level in (1, 2, 3):
        c = _build("asvs-4.0.3", max_level=level, suffix=f"-l{level}")
        out[c.id] = c
    return out


def get(checklist_id: str | None) -> Checklist | None:
    return catalogue().get(checklist_id) if checklist_id else None
