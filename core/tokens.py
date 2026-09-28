"""Scoped API tokens (Week 29 backfill, ADR-0018): the plan's §19.2 format — a recognizable
prefix, a checksum for typo detection, shown once, stored only as a SHA-256 hash. Pure logic only;
no DB access here (see `core/persistence/repo.py` for storage, `api/deps.py` for how a request
authenticates with one).
"""

from __future__ import annotations

import hashlib
import secrets
import zlib
from dataclasses import dataclass

PREFIX = "bulwark_"
_SECRET_BYTES = 20  # 40 hex chars of entropy
_CHECKSUM_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_CHECKSUM_LEN = 6

#: Real, enforced scopes today. Deliberately small: `issues:read` isn't listed here (unlike the
#: plan's example) because there is no dedicated issues endpoint yet (ADR-0012 already deferred
#: that) -- declaring a scope nothing checks would be a scope that lies about what it does. Add to
#: this set only alongside the endpoint it actually gates.
SCOPES = frozenset({"scans:read", "scans:write"})


class TokenError(ValueError):
    pass


def _checksum(body: str) -> str:
    """A CRC32-derived, fixed-width, base62 checksum -- the same purpose GitHub's own token format
    serves: catching a mistyped or truncated token before it ever reaches a lookup, not a security
    property (CRC32 is not cryptographic)."""
    n = zlib.crc32(body.encode())
    out = []
    for _ in range(_CHECKSUM_LEN):
        n, rem = divmod(n, len(_CHECKSUM_ALPHABET))
        out.append(_CHECKSUM_ALPHABET[rem])
    return "".join(reversed(out))


@dataclass(frozen=True)
class GeneratedToken:
    raw: str  # shown to the caller exactly once; never stored
    token_hash: str  # what's actually persisted
    display_prefix: str  # safe to show in a "your tokens" listing afterwards


def generate_token() -> GeneratedToken:
    secret = secrets.token_hex(_SECRET_BYTES)
    body = f"{PREFIX}{secret}"
    raw = f"{body}_{_checksum(body)}"
    return GeneratedToken(
        raw=raw, token_hash=hash_token(raw), display_prefix=raw[: len(PREFIX) + 6]
    )


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def verify_checksum(raw: str) -> bool:
    """Cheap, pre-hash sanity check: does this even look like one of our tokens? Doesn't touch the
    database, so a copy-paste error or a clearly-foreign token never reaches a hash lookup at all.
    """
    if not raw.startswith(PREFIX) or "_" not in raw[len(PREFIX) :]:
        return False
    body, _, checksum = raw.rpartition("_")
    return bool(body) and checksum == _checksum(body)


def parse_scopes(values: list[str]) -> frozenset[str]:
    unknown = [v for v in values if v not in SCOPES]
    if unknown:
        raise TokenError(f"unknown scope(s): {', '.join(unknown)}; valid: {sorted(SCOPES)}")
    return frozenset(values)
