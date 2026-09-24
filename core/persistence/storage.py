"""Object storage for raw scanner artifacts (S3 API: MinIO in dev, any S3 in prod)."""

from __future__ import annotations

from typing import Any, Protocol

import boto3
from botocore.exceptions import ClientError

from core.config import Settings


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
