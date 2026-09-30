"""core.secrets.envelope's AES-256-GCM encrypt/decrypt (Week 47 task 1, plan §22.2)."""

from __future__ import annotations

import pytest

from core.secrets import envelope


def test_roundtrip_recovers_the_original_plaintext() -> None:
    key = envelope.generate_local_key()
    blob = envelope.encrypt(key, b"raw tool output with a secret in it")
    assert envelope.decrypt(key, blob) == b"raw tool output with a secret in it"


def test_roundtrip_with_associated_data() -> None:
    key = envelope.generate_local_key()
    blob = envelope.encrypt(key, b"payload", associated_data=b"scans/abc/raw/bandit.json")
    assert envelope.decrypt(key, blob, associated_data=b"scans/abc/raw/bandit.json") == b"payload"


def test_wrong_associated_data_is_rejected() -> None:
    key = envelope.generate_local_key()
    blob = envelope.encrypt(key, b"payload", associated_data=b"scans/abc/raw/bandit.json")
    with pytest.raises(envelope.DecryptionError):
        envelope.decrypt(key, blob, associated_data=b"scans/OTHER/raw/bandit.json")


def test_wrong_key_is_rejected_not_a_wrong_plaintext() -> None:
    key = envelope.generate_local_key()
    other_key = envelope.generate_local_key()
    blob = envelope.encrypt(key, b"payload")
    with pytest.raises(envelope.DecryptionError):
        envelope.decrypt(other_key, blob)


def test_tampered_ciphertext_is_rejected() -> None:
    key = envelope.generate_local_key()
    blob = bytearray(envelope.encrypt(key, b"payload"))
    blob[-1] ^= 0xFF  # flip a bit in the GCM tag
    with pytest.raises(envelope.DecryptionError):
        envelope.decrypt(key, bytes(blob))


def test_two_encryptions_of_the_same_plaintext_produce_different_blobs() -> None:
    """A fresh random nonce per call -- ciphertext must not leak that two objects are identical."""
    key = envelope.generate_local_key()
    assert envelope.encrypt(key, b"same") != envelope.encrypt(key, b"same")


def test_wrong_key_size_is_rejected() -> None:
    with pytest.raises(ValueError):
        envelope.encrypt(b"too-short", b"payload")
    with pytest.raises(ValueError):
        envelope.decrypt(b"too-short", b"whatever-blob-goes-here")


def test_truncated_blob_is_rejected_not_indexed_out_of_range() -> None:
    key = envelope.generate_local_key()
    with pytest.raises(envelope.DecryptionError):
        envelope.decrypt(key, b"short")
