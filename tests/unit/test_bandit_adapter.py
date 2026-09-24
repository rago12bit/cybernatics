import json
from pathlib import Path

from core.adapters.bandit import BanditAdapter

GOLDEN = Path(__file__).parent.parent / "golden" / "bandit"


def test_parse_matches_golden() -> None:
    raw = (GOLDEN / "raw.json").read_bytes()
    expected = json.loads((GOLDEN / "expected.json").read_text())
    actual = [f.to_dict() for f in BanditAdapter().parse(raw)]
    assert json.loads(json.dumps(actual, sort_keys=True)) == expected


def test_parse_never_raises_on_garbage() -> None:
    a = BanditAdapter()
    assert a.parse(b"") == []
    assert a.parse(b"not json") == []
    assert a.parse(b'{"no_results": 1}') == []
    assert a.parse(b'{"results": [{"bogus": 1}]}') == []


def test_paths_are_relative_to_target() -> None:
    raw = (GOLDEN / "raw.json").read_bytes()
    assert all(not f.location.path.startswith("/") for f in BanditAdapter().parse(raw))
