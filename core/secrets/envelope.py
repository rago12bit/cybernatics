"""AES-256-GCM encryption of bytes with a plaintext data key (Week 47 task 1, plan §22.2).

The data key itself is minted and unwrapped by core.secrets.openbao's Transit client; this module
never talks to OpenBao and never persists a key -- it takes a plaintext key for the duration of one
call and nothing more. `associated_data` should be the object's own storage key (e.g.
"scans/<id>/raw/<tool>.json") wherever one exists: GCM authenticates it without encrypting it, so a
ciphertext can never be silently swapped onto a different object's key and still decrypt -- an
attacker who moved one scan's encrypted blob onto another scan's storage key gets a hard
DecryptionError, not a wrong-but-valid plaintext.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE_BYTES = 32  # AES-256
_NONCE_SIZE_BYTES = 12  # the standard, recommended GCM nonce size


class DecryptionError(Exception):
    pass


def generate_local_key() -> bytes:
    """A fresh, random 32-byte key -- used only by tests and fakes; real data keys come from
    core.secrets.openbao.generate_data_key, never from this function."""
    return os.urandom(KEY_SIZE_BYTES)


def encrypt(data_key: bytes, plaintext: bytes, *, associated_data: bytes | None = None) -> bytes:
    """Returns nonce || ciphertext-with-tag, self-contained so decrypt() needs nothing else."""
    if len(data_key) != KEY_SIZE_BYTES:
        raise ValueError(f"data key must be {KEY_SIZE_BYTES} bytes, got {len(data_key)}")
    nonce = os.urandom(_NONCE_SIZE_BYTES)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(data_key: bytes, blob: bytes, *, associated_data: bytes | None = None) -> bytes:
    """Raises DecryptionError for a wrong key, a tampered blob, or mismatched associated_data --
    never returns a plausible-looking wrong plaintext."""
    if len(data_key) != KEY_SIZE_BYTES:
        raise ValueError(f"data key must be {KEY_SIZE_BYTES} bytes, got {len(data_key)}")
    if len(blob) < _NONCE_SIZE_BYTES:
        raise DecryptionError("ciphertext blob is shorter than one nonce")
    nonce, ciphertext = blob[:_NONCE_SIZE_BYTES], blob[_NONCE_SIZE_BYTES:]
    try:
        result: bytes = AESGCM(data_key).decrypt(nonce, ciphertext, associated_data)
        return result
    except InvalidTag as exc:
        raise DecryptionError("authentication failed: wrong key, tampered data, or wrong "
                               "associated_data") from exc  # fmt: skip
