"""core.persistence.storage's EncryptingObjectStore and build_object_store wiring (Week 47 task 1,
plan §22.2). The real OpenBao client is live-tested elsewhere
(tests/integration/test_secrets_openbao_docker.py); this covers the decorator and factory logic with
a fake key resolver / fake OpenBao client."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings
from core.persistence import repo
from core.persistence.storage import (
    EncryptingObjectStore,
    MemoryStore,
    _resolve_scan_data_key,
    _scan_id_from_key,
    build_object_store,
)
from core.secrets import envelope
from core.secrets.openbao import DataKey
from core.tenancy import DEFAULT_ORG_ID


def test_put_then_get_roundtrips_through_encryption() -> None:
    key_bytes = envelope.generate_local_key()
    store = EncryptingObjectStore(MemoryStore(), resolve_key=lambda k: key_bytes)
    store.put("scans/s1/raw/bandit.json", b"the real raw output")
    assert store.get("scans/s1/raw/bandit.json") == b"the real raw output"


def test_underlying_store_never_sees_plaintext() -> None:
    key_bytes = envelope.generate_local_key()
    inner = MemoryStore()
    EncryptingObjectStore(inner, resolve_key=lambda k: key_bytes).put(
        "scans/s1/raw/bandit.json", b"secret finding text"
    )
    assert b"secret finding text" not in inner.objects["scans/s1/raw/bandit.json"]


def test_a_ciphertext_cannot_be_read_back_under_a_different_key() -> None:
    inner = MemoryStore()
    key_a, key_b = envelope.generate_local_key(), envelope.generate_local_key()
    store_a = EncryptingObjectStore(inner, resolve_key=lambda k: key_a)
    store_a.put("scans/s1/raw/bandit.json", b"data")
    store_b = EncryptingObjectStore(inner, resolve_key=lambda k: key_b)
    with pytest.raises(envelope.DecryptionError):
        store_b.get("scans/s1/raw/bandit.json")


def test_a_ciphertext_moved_to_a_different_key_string_cannot_be_read_back() -> None:
    """The storage key itself is authenticated (associated_data) -- copying one object's ciphertext
    onto another key must fail closed, not decrypt into the wrong scan's data."""
    key_bytes = envelope.generate_local_key()
    inner = MemoryStore()
    store = EncryptingObjectStore(inner, resolve_key=lambda k: key_bytes)
    store.put("scans/s1/raw/bandit.json", b"data")
    inner.objects["scans/s2/raw/bandit.json"] = inner.objects["scans/s1/raw/bandit.json"]
    with pytest.raises(envelope.DecryptionError):
        store.get("scans/s2/raw/bandit.json")


def test_scan_id_from_key_parses_the_real_convention() -> None:
    assert _scan_id_from_key("scans/abc-123/raw/bandit.json") == "abc-123"


def test_scan_id_from_key_rejects_an_unexpected_shape() -> None:
    with pytest.raises(ValueError):
        _scan_id_from_key("not-a-scan-key")


def test_build_object_store_returns_plain_store_when_openbao_is_unconfigured(tmp_path: Any) -> None:
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token="t", workdir=tmp_path, upload_dir=tmp_path / "u", max_upload_bytes=1,
    )  # fmt: skip
    store = build_object_store(settings, sessions=lambda: None, org_id=DEFAULT_ORG_ID)  # type: ignore[arg-type]
    assert not isinstance(store, EncryptingObjectStore)


def test_build_object_store_returns_plain_store_when_org_id_is_none(tmp_path: Any) -> None:
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token="t", workdir=tmp_path, upload_dir=tmp_path / "u", max_upload_bytes=1,
        openbao_addr="http://openbao:8200", openbao_token="t",
    )  # fmt: skip
    store = build_object_store(settings, sessions=lambda: None, org_id=None)  # type: ignore[arg-type]
    assert not isinstance(store, EncryptingObjectStore)


def test_build_object_store_wraps_when_openbao_is_configured(tmp_path: Any) -> None:
    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="", s3_secret_key="",
        s3_bucket="b", api_token="t", workdir=tmp_path, upload_dir=tmp_path / "u", max_upload_bytes=1,
        openbao_addr="http://openbao:8200", openbao_token="t",
    )  # fmt: skip
    store = build_object_store(settings, sessions=lambda: None, org_id=DEFAULT_ORG_ID)  # type: ignore[arg-type]
    assert isinstance(store, EncryptingObjectStore)


def test_resolve_scan_data_key_mints_once_then_reuses_the_stored_wrapped_key(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git",
            source_label="acme/x", tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        scan_id = scan.id

    class FakeClient:
        def __init__(self) -> None:
            self.generate_calls = 0
            self.unwrap_calls = 0
            self._key = envelope.generate_local_key()

        def ensure_org_key(self, org_id: str) -> None:
            pass

        def generate_data_key(self, org_id: str) -> DataKey:
            self.generate_calls += 1
            return DataKey(plaintext=self._key, wrapped="vault:v1:fixed")

        def unwrap_data_key(self, org_id: str, wrapped: str) -> bytes:
            self.unwrap_calls += 1
            assert wrapped == "vault:v1:fixed"
            return self._key

    client = FakeClient()
    first = _resolve_scan_data_key(sessions, client, DEFAULT_ORG_ID, scan_id)  # type: ignore[arg-type]
    second = _resolve_scan_data_key(sessions, client, DEFAULT_ORG_ID, scan_id)  # type: ignore[arg-type]
    assert first == second == client._key
    assert client.generate_calls == 1  # minted once
    assert client.unwrap_calls == 1  # then looked up and unwrapped, not re-minted
