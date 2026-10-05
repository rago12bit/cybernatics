"""The deterministic half of the mapper eval: runs a reply through the REAL
`core.imports.mapper.sanitize`, the exact check `propose_with_model` applies -- against the
fixture's own sample analysis (`fixtures/meta.json`). A reply passes only if nothing in it had to be
dropped (no invented path, field, severity or records path) and it maps the fields a person would
expect for that sample, to the same paths."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.imports.mapper import sanitize

META = json.loads((Path(__file__).parent / "fixtures" / "meta.json").read_text())


def get_assert(output: str, context: dict[str, Any]) -> dict[str, Any]:
    fixture = META[(context.get("vars") or {})["fixture"]]
    text = output.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
    try:
        reply = json.loads(text)
    except ValueError:
        return {"pass": False, "score": 0.0, "reason": "the reply is not one JSON object"}
    if not isinstance(reply, dict):
        return {"pass": False, "score": 0.0, "reason": "the reply is not a JSON object"}
    spec, dropped = sanitize(reply, fixture["analysis"], "eval")
    if dropped:
        return {"pass": False, "score": 0.0, "reason": f"invented or invalid: {dropped}"}
    wrong = {k: spec["fields"].get(k) for k, v in fixture["expect"].items()
             if spec["fields"].get(k) != v}  # fmt: skip
    if wrong:
        return {"pass": False, "score": 0.5, "reason": f"expected fields not mapped: {wrong}"}
    return {"pass": True, "score": 1.0, "reason": f"valid draft: {sorted(spec['fields'])}"}
