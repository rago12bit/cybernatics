"""Object storage for raw scanner artifacts (S3 API: MinIO in dev, any S3 in prod)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import boto3
from botocore.exceptions import ClientError

from core.config import Settings
from core.persistence import repo
from core.persistence.db import SessionFactory
from core.secrets import envelope
from core.secrets.openbao import OpenBaoClient, decode_wrapped_key, encode_wrapped_key


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...


class S3Store:
    def __init__(self, settings: Settings) -> None:
        self._bucket = settings.s3_bucket
        self._client: Any = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            region_name="us-east-1",
        )

    def ensure_bucket(self) -> None:
        try:
            self._client.head_bucket(Bucket=self._bucket)
        except ClientError:
            self._client.create_bucket(Bucket=self._bucket)

    def put(self, key: str, data: bytes) -> None:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data)

    def get(self, key: str) -> bytes:
        body: bytes = self._client.get_object(Bucket=self._bucket, Key=key)["Body"].read()
        return body


class MemoryStore:
    """In-memory ObjectStore for tests."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, key: str, data: bytes) -> None:
        self.objects[key] = data

    def get(self, key: str) -> bytes:
        return self.objects[key]


class EncryptingObjectStore:
    """Wraps any ObjectStore, transparently envelope-encrypting on put and decrypting on get (Week
    47 task 1, plan §22.2, ADR-0032). This class never talks to OpenBao or the database itself:
    `resolve_key(key)` supplies the plaintext data key for a given storage key, injected by the
    caller (core.pipeline mints/looks up a scan's key via core.persistence.repo.ScanDataKeyRow and
    core.secrets.openbao) so this module stays a pure decorator, easy to test with a fake key
    resolver instead of a real OpenBao instance.

    The storage key itself is passed as AEAD associated data (core.secrets.envelope), so a
    ciphertext can never be silently swapped onto a different key's object and still decrypt.
    """

    def __init__(self, inner: ObjectStore, resolve_key: Callable[[str], bytes]) -> None:
        self._inner = inner
        self._resolve_key = resolve_key

    def put(self, key: str, data: bytes) -> None:
        data_key = self._resolve_key(key)
        blob = envelope.encrypt(data_key, data, associated_data=key.encode())
        self._inner.put(key, blob)

    def get(self, key: str) -> bytes:
        data_key = self._resolve_key(key)
        blob = self._inner.get(key)
        return envelope.decrypt(data_key, blob, associated_data=key.encode())


def build_object_store(
    settings: Settings, sessions: SessionFactory, org_id: str | None
) -> ObjectStore:
    """The real ObjectStore a scan job stores its raw tool output through
    (core.tasks.run_scan_task): plain S3Store when OpenBao isn't configured or the org is unknown --
    the same "off means off, not a silent partial feature" posture as the GitHub App integration --
    envelope-encrypted (Week 47 task 1, plan §22.2) otherwise."""
    base = S3Store(settings)
    if not settings.openbao_addr or not settings.openbao_token or org_id is None:
        return base
    client = OpenBaoClient(addr=settings.openbao_addr, token=settings.openbao_token)
    return EncryptingObjectStore(
        base, lambda key: _resolve_scan_data_key(sessions, client, org_id, _scan_id_from_key(key))
    )


def _scan_id_from_key(key: str) -> str:
    """Every object key core.pipeline._store_raw writes is "scans/<scan_id>/raw/<tool>.json" -- a
    convention, not something this module enforces on writers, so this raises clearly if a future
    caller ever passes a differently-shaped key through an encrypting store rather than silently
    misattributing it to the wrong scan's data key."""
    parts = key.split("/")
    if len(parts) < 2 or parts[0] != "scans":
        raise ValueError(f"cannot determine scan_id from object key: {key!r}")
    return parts[1]


def _resolve_scan_data_key(
    sessions: SessionFactory, client: OpenBaoClient, org_id: str, scan_id: str
) -> bytes:
    """One data key per scan, reused for every object that scan writes: minted on first use, then
    looked up and unwrapped on every call after (including every read) rather than re-minted."""
    with sessions() as s:
        row = repo.get_scan_data_key(s, scan_id)
    if row is not None:
        return client.unwrap_data_key(org_id, decode_wrapped_key(row.wrapped_dek))
    client.ensure_org_key(org_id)
    data_key = client.generate_data_key(org_id)
    with sessions() as s:
        repo.save_scan_data_key(s, scan_id, org_id, encode_wrapped_key(data_key.wrapped))
    return data_key.plaintext
