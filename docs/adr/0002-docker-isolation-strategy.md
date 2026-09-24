# ADR-002: One sandboxed Docker container per scanner

Status: Accepted (2026-09-24)

## Context
The scanner ingests attacker-controlled code and runs third-party tools over it (threats T1, T2, T6, T10).

## Decision
Each tool runs in its own ephemeral container with: `--network=none`, `--read-only`,
`--cap-drop=ALL`, `--security-opt=no-new-privileges`, non-root UID, `--memory=2g --cpus=1.0`,
PID limit, wall-clock timeout, target mounted read-only, and a single writable output dir.
Images are pinned by SHA-256 digest in production. Dependencies are never installed.
Production hardening: rootless Docker or gVisor.

## Consequences
- Tools needing network (OSV-Scanner online mode, Trivy DB) must use pre-fetched offline databases.
- Per-container overhead is accepted for isolation.
