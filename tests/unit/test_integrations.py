"""The public integrations catalogue (Week 77, plan §57) is generated from the code's registries.

These tests are what keep it from drifting: the committed web/lib/integrations.json must be exactly
what scripts/gen-integrations.py generates now, and every entry in every registry must be on it --
a parser, scanner or connector added without regenerating fails here, not on the website.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "gen_integrations", ROOT / "scripts/gen-integrations.py"
)
assert _spec and _spec.loader
gen = importlib.util.module_from_spec(_spec)
sys.modules["gen_integrations"] = gen
_spec.loader.exec_module(gen)


def _ids() -> set[str]:
    return {i["id"] for i in gen.catalogue()["items"]}


def test_the_committed_catalogue_is_what_the_registries_generate() -> None:
    actual = (ROOT / "web/lib/integrations.json").read_text()
    assert (
        actual == gen.render()
    ), "web/lib/integrations.json is stale: run scripts/gen-integrations.py"


def test_every_scanner_parser_and_connector_is_listed() -> None:
    from core.connectors.service import KINDS
    from core.dast.campaign import TOOLS_FOR_MODE
    from core.imports.parsers.registry import PARSERS
    from core.notify.kinds import PERSON_CHANNELS
    from core.scan import ADAPTERS
    from core.tickets.config import PROVIDERS

    want = (
        {f"scanner:{n}" for n in ADAPTERS}
        | {f"scanner:{t}" for tools in TOOLS_FOR_MODE.values() for t in tools}
        | {f"import:{n}" for n in PARSERS}
        | {"import:universal"}
        | {f"connector:{k}" for k in KINDS}
        | {f"tickets:{p}" for p in PROVIDERS}
        | {f"notify:{c}" for c in PERSON_CHANNELS}
    )
    assert want <= _ids()


def test_team_channels_name_real_senders() -> None:
    """The hand-written channel list must name modules that exist, so a removed sender cannot
    stay advertised."""
    for module in gen.TEAM_CHANNELS:
        assert (ROOT / "core/integrations" / f"{module}.py").is_file(), module


def test_categories_used_have_labels_and_ids_are_unique() -> None:
    cat = gen.catalogue()
    items = cat["items"]
    assert len({i["id"] for i in items}) == len(items)
    used = {c for i in items for c in i.get("categories", [])}
    assert used <= set(cat["categories"]), used - set(cat["categories"])
    assert all(i["how"] and i["name"] for i in items)


def test_ported_parsers_are_marked() -> None:
    items = {i["id"]: i for i in gen.catalogue()["items"]}
    assert items["import:zap"]["ported_from_defectdojo"] is True
    assert items["import:sarif"]["ported_from_defectdojo"] is False
    assert json.loads(gen.render())["items"] == gen.catalogue()["items"]
