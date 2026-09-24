# ADR-007: Any S3-compatible store for raw artifacts; RustFS in the dev stack

Status: Accepted (2026-09-24)

## Context
The design doc specified "MinIO/S3" for raw tool output. When building Week 5, the official
`minio/minio` Docker Hub image no longer exists and the `quay.io/minio/minio` mirror returns 401,
so MinIO cannot be pulled by a clean `docker compose up`.

## Decision
The code depends only on the S3 API (`boto3` with a configurable endpoint), never on MinIO.
The compose stack uses RustFS (Apache-2.0, S3-compatible, multi-arch). Production can point
`BULWARK_S3_ENDPOINT` at AWS S3, Cloudflare R2 or any compatible service.

## Consequences
- Swapping the store is a config change; verified by exercising bucket creation and put/get.
- RustFS is younger than MinIO; the image is currently `:latest` and must be pinned by digest
  before any production use (ADR-002).
