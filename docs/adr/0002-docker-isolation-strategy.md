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

## Amendment (2026-09-24, Week 5): running inside docker compose
The worker must launch scanner containers, i.e. it needs Docker access. Mounting the raw socket
would make a compromised worker equivalent to root on the host, so it instead reaches the daemon
through `tecnativa/docker-socket-proxy`, allowing only container create/start/kill, image
inspect and volumes. Scan workspaces live in a directory bind-mounted at the *same path* in the
worker and on the host, because sibling containers are started by the host daemon.

Residual risk (accepted for v0.x, must be addressed before any public deployment): the proxy
still permits creating containers with arbitrary host bind mounts. Production should use a
dedicated runner service on an isolated host, or gVisor/rootless Docker, with the worker holding
no Docker access at all.
