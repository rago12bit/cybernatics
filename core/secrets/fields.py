"""Encrypting individual database columns that hold a credential (the Slack/Discord/Teams webhook
URLs, the GitHub token, the Jira API token, the webhook secrets in `IntegrationSettingsRow`).

`EncryptedText` is a column type: code reads and writes plain strings, and the database holds
`enc:v1:<base64 of nonce || AES-256-GCM ciphertext>`. The associated data is the column's own label
("integration_settings.github_token"), so a ciphertext copied into another column does not decrypt.

The key is one 32-byte value, hex-encoded, from `BULWARK_SECRETS_KEY` or OpenBao's KV store at
`bulwark/secrets-key` (`core.secrets.resolve.resolve_secret`, like every other server secret), and
never stored in the database. Without a key, values are written in plain text as before, with a
warning; with one, plain-text values already stored still read, and are encrypted the next time they
are written (`bulwark secrets encrypt-stored` rewrites them all).

A value that cannot be decrypted (no key, a different key, tampering) reads as None, with an error
in the log: the integration is then off rather than pointed at something nobody can vouch for.
"""

from __future__ import annotations

import base64
import binascii
import logging
from functools import lru_cache

from sqlalchemy import Text
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator

from core.secrets import envelope
from core.secrets.resolve import resolve_secret

log = logging.getLogger(__name__)

PREFIX = "enc:v1:"
ENV_VAR = "BULWARK_SECRETS_KEY"
KV_PATH = "bulwark/secrets-key"


class SecretsKeyError(ValueError):
    """BULWARK_SECRETS_KEY is set but is not 64 hex characters (32 bytes)."""


@lru_cache(maxsize=1)
def _key() -> bytes | None:
    raw = resolve_secret(ENV_VAR, kv_path=KV_PATH).strip()
    if not raw:
        return None
    try:
        key = binascii.unhexlify(raw)
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != envelope.KEY_SIZE_BYTES:
        raise SecretsKeyError(f"{ENV_VAR} must be 64 hex characters (openssl rand -hex 32)")
    return key


def key_configured() -> bool:
    return _key() is not None


def reset_key_cache() -> None:
    """Read the key again on next use (tests, and after the environment changes)."""
    _key.cache_clear()
    _warned.clear()


_warned: set[str] = set()


def encrypt_value(value: str, label: str) -> str:
    key = _key()
    if key is None:
        if label not in _warned:
            _warned.add(label)
            log.warning("%s is not set: storing %s unencrypted", ENV_VAR, label)
        return value
    blob = envelope.encrypt(key, value.encode(), associated_data=label.encode())
    return PREFIX + base64.b64encode(blob).decode()


def decrypt_value(stored: str, label: str) -> str | None:
    if not stored.startswith(PREFIX):
        return stored  # written before encryption was turned on
    key = _key()
    if key is None:
        log.error("%s is encrypted but %s is not set; treating it as unset", label, ENV_VAR)
        return None
    try:
        blob = base64.b64decode(stored[len(PREFIX) :], validate=True)
        return envelope.decrypt(key, blob, associated_data=label.encode()).decode()
    except (binascii.Error, ValueError, envelope.DecryptionError):
        log.error("%s does not decrypt with this %s; treating it as unset", label, ENV_VAR)
        return None


class EncryptedText(TypeDecorator[str]):
    """A Text column whose values are encrypted at rest (see the module docstring)."""

    impl = Text
    cache_ok = True

    def __init__(self, label: str) -> None:
        super().__init__()
        self.label = label

    def process_bind_param(self, value: str | None, dialect: Dialect) -> str | None:
        return None if value is None else encrypt_value(value, self.label)

    def process_result_value(self, value: str | None, dialect: Dialect) -> str | None:
        return None if value is None else decrypt_value(value, self.label)
