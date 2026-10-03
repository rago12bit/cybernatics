"""Ported parsers against DefectDojo's own sample reports and its tests' expected results
(plan §59 Week 57, §60). The fixtures and expectations are vendored by scripts/sync-dd-fixtures.py
(BSD-3-Clause, see tests/golden/ingest/defectdojo/LICENSE); `ddview` explains how our output is
regrouped so the comparison is like for like.

Every difference between a parser here and DefectDojo's is either in `DIFFERENCES` with the reason,
or a failure. None is silent.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from core.imports.parsers import get_parser, run_parser_on_bytes
from tests.unit import ddview

TOOLS = ["zap", "nuclei"]

# (tool, file, test, finding index, field) -> why ours differs from what DefectDojo's test asserts.
# Reviewed one by one; each is a deliberate decision, not a miss.
DIFFERENCES: dict[tuple[str, str, str, str, str], str] = {}


def _cases() -> list[Any]:
    cases = []
    for tool in TOOLS:
        m = ddview.manifest(tool)
        for name, info in sorted(m["files"].items()):
            marks = (
                [] if info["vendored"] else [pytest.mark.skip(reason="over the vendoring limit")]
            )
            cases.append(pytest.param(tool, name, info, id=f"{tool}/{name}", marks=marks))
    return cases


@pytest.mark.parametrize("tool,name,info", _cases())
def test_matches_defectdojo(tool: str, name: str, info: dict[str, Any]) -> None:
    data = (ddview.GOLDEN / tool / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == info["sha256"], "fixture changed since vendoring"

    parser = get_parser(tool)
    result = run_parser_on_bytes(parser, data)
    assert result.error is None, f"{name}: {result.error}"
    assert (
        parser.sniff(data[:65536]) > 0 or len(data) == 0
    ), "sniff() does not recognise its own sample"

    groups = ddview.GROUPERS[tool](result.findings)
    for exp in info["expect"]:
        where = f"{tool}/{name}::{exp['test']}"
        if "count" in exp:
            assert len(groups) == exp["count"], f"{where}: findings"
        for index, fields in exp.get("findings", {}).items():
            got = ddview.view(tool, groups[int(index)])
            for field, want in fields.items():
                want = 0 if (field == "cwe" and want is None) else want
                reason = DIFFERENCES.get((tool, name, exp["test"], index, field))
                if reason:
                    assert got[field] != want, f"{where}[{index}].{field}: no longer differs"
                    continue
                assert got[field] == want, f"{where}[{index}].{field}"
