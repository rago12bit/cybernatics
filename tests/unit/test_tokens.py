from __future__ import annotations

import pytest

from core.tokens import (
    PREFIX,
    TokenError,
    generate_token,
    hash_token,
    parse_scopes,
    verify_checksum,
)


def test_generated_token_has_the_right_shape() -> None:
    t = generate_token()
    assert t.raw.startswith(PREFIX)
    assert t.raw.count("_") == 2  # "bulwark" _ <secret> _ <checksum>
    assert t.token_hash == hash_token(t.raw)
    assert t.display_prefix == t.raw[: len(PREFIX) + 6]


def test_every_token_is_unique() -> None:
    assert len({generate_token().raw for _ in range(50)}) == 50


def test_checksum_catches_a_typo() -> None:
    t = generate_token()
    assert verify_checksum(t.raw) is True
    mutated = t.raw[:-1] + ("0" if t.raw[-1] != "0" else "1")
    assert verify_checksum(mutated) is False


def test_checksum_rejects_anything_not_shaped_like_our_token() -> None:
    for bad in ["", "ghp_abcdef", "bulwark_", "bulwark_nounderscorechecksum", "not-even-close"]:
        assert verify_checksum(bad) is False


def test_hash_is_sha256_hex_and_deterministic() -> None:
    raw = generate_token().raw
    h = hash_token(raw)
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
    assert hash_token(raw) == h


def test_parse_scopes_accepts_known_and_rejects_unknown() -> None:
    assert parse_scopes(["scans:read", "scans:write"]) == {"scans:read", "scans:write"}
    with pytest.raises(TokenError, match="unknown scope"):
        parse_scopes(["scans:read", "sudo:everything"])
