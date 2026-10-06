from __future__ import annotations

import json

from core.audit_rekor import _extract_log_index


def test_extracts_log_index_from_a_real_shaped_sigstore_bundle() -> None:
    bundle = json.dumps(
        {"verificationMaterial": {"tlogEntries": [{"logIndex": 123456, "logId": {}}]}}
    )
    assert _extract_log_index(bundle) == 123456


def test_returns_none_rather_than_raising_on_an_unexpected_shape() -> None:
    for bad in ["{}", '{"verificationMaterial": {}}', '{"verificationMaterial": {"tlogEntries": []}}',
                "not even json", '{"verificationMaterial": {"tlogEntries": [{"logIndex": "oops"}]}}']:  # fmt: skip
        assert _extract_log_index(bad) is None


def test_reads_the_index_as_cosign_3_writes_it() -> None:
    """Protobuf JSON: the index is a string, and an index of 0 is left out (real bundles from a
    local Rekor, tests/fixtures/rekor)."""
    from pathlib import Path

    fixtures = Path(__file__).parent.parent / "fixtures" / "rekor"
    assert _extract_log_index((fixtures / "index-0.bundle").read_text()) == 0
    assert _extract_log_index((fixtures / "index-1.bundle").read_text()) == 1
    assert _extract_log_index('{"verificationMaterial": {"tlogEntries": []}}') is None
