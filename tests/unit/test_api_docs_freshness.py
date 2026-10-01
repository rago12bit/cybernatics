"""docs/api.md and docs/openapi.json must match what `scripts/gen-api-docs.py` would generate from
the live FastAPI app right now -- the gap this closes: Weeks 48-50's asset/web, threat-model,
copilot and cost-dashboard endpoints, and Week 51 tasks 1-2's /plugins and /settings/integrations,
all shipped without anyone noticing these two files had gone stale, because nothing checked them
(docs/severity-matrix.md had exactly this kind of freshness check already, in
tests/unit/test_correlation.py -- these two did not).

Loads scripts/gen-api-docs.py directly (same importlib.util technique tests/unit/test_licenses.py
already uses for scripts/gen-licenses.py: a hyphenated filename isn't a valid module name) and
re-derives both files' expected content from the running app, rather than re-implementing the
derivation here -- so this test can't itself drift from what the generator actually does.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("gen_api_docs", ROOT / "scripts" / "gen-api-docs.py")
assert _spec and _spec.loader
gen_api_docs = importlib.util.module_from_spec(_spec)
sys.modules["gen_api_docs"] = gen_api_docs
_spec.loader.exec_module(gen_api_docs)


def test_openapi_json_matches_the_live_app() -> None:
    expected = json.dumps(gen_api_docs.openapi_spec(), indent=2) + "\n"
    actual = (ROOT / "docs" / "openapi.json").read_text()
    assert actual == expected, "docs/openapi.json is stale: run scripts/gen-api-docs.py"


def test_api_md_matches_the_live_app() -> None:
    expected = gen_api_docs.api_doc(gen_api_docs.openapi_spec())
    actual = (ROOT / "docs" / "api.md").read_text()
    assert actual == expected, "docs/api.md is stale: run scripts/gen-api-docs.py"
