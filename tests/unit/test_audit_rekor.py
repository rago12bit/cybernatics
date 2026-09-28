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
