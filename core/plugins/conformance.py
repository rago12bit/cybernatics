"""The Plugin SDK's conformance kit (Week 51 task 1, plan §23): "the same golden-file tests as
built-in adapters" literally means the same code, not a lookalike reimplementation. These four
checks are extracted unchanged from tests/unit/test_adapters.py's own parametrized harness --
tests/unit/test_adapters.py now imports and calls these same functions for every built-in adapter,
so there is exactly one implementation of "what a conforming ToolAdapter must do," shared by Bulwark
itself and by every third-party plugin.

A plugin author installs `bulwark` (this package already ships it; no separate distribution), then
writes one pytest test:

    from pathlib import Path
    from core.plugins.conformance import run_conformance_kit
    from my_plugin.adapter import MyAdapter

    def test_bulwark_conformance() -> None:
        run_conformance_kit(MyAdapter(), Path(__file__).parent / "golden")

`golden_dir` must contain `raw.json` (one real sample of the tool's raw output) and `expected.json`
(the exact `[f.to_dict() for f in adapter.parse(raw)]`, pretty-printed and committed) -- same shape
docs/adding-a-scanner.md already documents for built-ins.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from core.adapters import ToolAdapter
from core.models import finding_from_dict

#: Byte strings no real tool ever emits but a hostile or merely broken one might: empty output, text
#: that isn't JSON, valid-but-empty JSON in both shapes a tool-specific parser might expect, and
#: JSON whose records are missing the keys `parse()` looks for. `ToolAdapter.parse()`'s own contract
#: (core/adapters/base.py) is "never raise, return [] instead" -- these are what that promise is
#: actually tested against.
DEFAULT_GARBAGE: tuple[bytes, ...] = (
    b"",
    b"not json",
    b"{}",
    b"[]",
    b'{"results": [{"bogus": 1}]}',
    b'[{"x": 1}]',
)


def assert_matches_golden(adapter: ToolAdapter, golden_dir: Path) -> None:
    """`adapter.parse(raw.json)` must equal `expected.json` exactly, and must not be empty -- an
    adapter whose golden fixture parses to zero findings has almost certainly broken its own
    parsing, not found a genuinely clean sample."""
    expected = json.loads((golden_dir / "expected.json").read_text())
    actual = [f.to_dict() for f in adapter.parse((golden_dir / "raw.json").read_bytes())]
    assert actual, "golden fixture must produce findings"
    assert json.loads(json.dumps(actual, sort_keys=True)) == expected


def assert_never_raises_on_garbage(
    adapter: ToolAdapter, garbage_samples: Iterable[bytes] = DEFAULT_GARBAGE
) -> None:
    """A tool crashing, being killed mid-write, or emitting a format change must degrade to "no
    findings from this tool," never crash the whole scan -- this is the contract the sandbox's
    parallel tool execution (core.pipeline) depends on to isolate one tool's failure from the rest.
    """
    for garbage in garbage_samples:
        assert adapter.parse(garbage) == [], f"parse() raised or returned findings for {garbage!r}"


def assert_paths_relative_to_target(adapter: ToolAdapter, golden_dir: Path) -> None:
    """A Finding carrying an absolute path would leak the sandbox's internal mount point
    (core.adapters.base.TARGET_PREFIX) into API responses and reports -- every path must be relative
    to the scanned target, the same way a built-in adapter's is."""
    raw = (golden_dir / "raw.json").read_bytes()
    assert all(not f.location.path.startswith("/") for f in adapter.parse(raw))


def assert_findings_survive_json_roundtrip(adapter: ToolAdapter, golden_dir: Path) -> None:
    """Every Finding a plugin produces is persisted as JSON (core.persistence) and replayed back
    through finding_from_dict -- a field that doesn't survive that round trip would silently corrupt
    on the very first scan it's used in, not in some later edge case."""
    raw = (golden_dir / "raw.json").read_bytes()
    for f in adapter.parse(raw):
        assert finding_from_dict(json.loads(json.dumps(f.to_dict()))) == f


def run_conformance_kit(adapter: ToolAdapter, golden_dir: Path) -> None:
    """Runs every check above against one adapter instance. Raises AssertionError (pytest-friendly)
    on the first failure, naming which check failed."""
    assert_matches_golden(adapter, golden_dir)
    assert_never_raises_on_garbage(adapter)
    assert_paths_relative_to_target(adapter, golden_dir)
    assert_findings_survive_json_roundtrip(adapter, golden_dir)
