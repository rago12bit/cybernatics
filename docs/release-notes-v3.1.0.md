# Bulwark 3.1.0 — release notes

Released 2026-10-13. Every change is in
[CHANGELOG.md](https://github.com/rago12bit/cybernatics/blob/main/CHANGELOG.md), under 3.1.0.

> **The usability study still has not run.** 3.0.0 was released without it
> ([ux-study.md](ux-study.md)), and nothing in this release changes that. This is the first tag whose
> release workflow includes the registry login that signing needs; 3.0.0's image and provenance were
> published, but its signing step failed.

## Highlights

**Code intelligence for more frameworks.** A scan's route map now comes from the code graph: Django,
Express, Next.js and Go's net/http as well as FastAPI and Flask, with each framework's path parameters
normalized. A route's path includes where its router is mounted (Django `include()`, FastAPI
`include_router`, Flask blueprints, Express `use`), so SAST/DAST correlation, the attack surface, taint
paths, attack paths and the threat model show `/api/users/{id}`, not `/{id}`. On nine apps in the
evaluation corpus, 73 of 265 routes changed, every one checked by hand.

**Firecracker for the fix agent's test runs**, on a Linux host with KVM: a project's tests run in a
microVM with no network. The guest side was booted under QEMU; Firecracker itself has not run yet.

**A web target's link to its code**, chosen when the site is registered and changed later on its
verification page, without resetting the site's verification.

**Faster rules engine.** One dispatcher handles about 880 events a second, from 520.

## Fixes worth knowing about

- **Taint analysis converges.** Around a call cycle a function's summary grew on every pass; scanning
  Bulwark's own code passed 20 GB. It now takes 219 MB and 6 s.
- **The GitHub Action works on Linux runners.** With the result cache on (its default), Semgrep and
  Gitleaks could not read the files they were given; a plain `pip install` left out the taint catalogs
  and other data files; a breached threshold ended the gate step before its result was recorded; and a
  copied or moved file's cached findings were reported at the original's path.
- **DAST:** Nuclei no longer stalls behind the egress proxy or reaches past it, keeps its findings on a
  timeout, and the proxy checks every request on a connection. ZAP no longer closes Issues at pages its
  spider simply didn't reach this time.
- **Production CSP:** code highlighting and the threat-model diagram work under it, and CI now opens
  every page of the production build under the production policy.

## Upgrading

Migration 0051 (held ZAP places) runs with `alembic upgrade head`. The linters in the `dev` extra
are now pinned exactly (ruff 0.17.0, black 26.10.1, mypy 2.4.0).
