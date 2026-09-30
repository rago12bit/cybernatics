from __future__ import annotations

import pytest

from core.attackpath.contract import ContractError, validate_narrative


def test_accepts_prose_mentioning_every_label():
    text = validate_narrative(
        "A public route reaches the SSRF issue, which exposes the cloud metadata service.",
        node_labels=("SSRF issue", "cloud metadata service"),
    )
    assert "SSRF issue" in text


def test_rejects_reply_missing_a_node_label():
    with pytest.raises(ContractError, match="omits"):
        validate_narrative(
            "A public route reaches the SSRF issue.",
            node_labels=("SSRF issue", "cloud metadata service"),
        )


def test_rejects_markdown_bullets():
    with pytest.raises(ContractError, match="markdown"):
        validate_narrative("- SSRF issue\n- cloud metadata service", node_labels=("SSRF issue",))


def test_rejects_code_fence():
    with pytest.raises(ContractError, match="prose"):
        validate_narrative("```SSRF issue```", node_labels=("SSRF issue",))


def test_rejects_json():
    with pytest.raises(ContractError, match="JSON"):
        validate_narrative('{"text": "SSRF issue"}', node_labels=("SSRF issue",))


def test_rejects_empty_reply():
    with pytest.raises(ContractError, match="empty"):
        validate_narrative("   ", node_labels=())


def test_case_insensitive_label_match():
    validate_narrative("the ssrf issue is reachable", node_labels=("SSRF issue",))
