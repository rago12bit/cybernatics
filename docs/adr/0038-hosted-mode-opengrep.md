# ADR-0038: Hosted mode runs Opengrep, not Semgrep

Status: Implemented (2026-10-02), Week 53 task 2 (plan §39.5/§40, "ADR-015" in the plan's own
numbering -- renumbered to this repository's real, sequential ADR series).

## Context

ADR-006 already established that Semgrep's community/Pro rules (`docker/semgrep/`) are licensed
under the Semgrep Rules License v1.0: internal business use only, no redistribution, no offering
them as a service. That was a non-issue for v1/early v2, since Bulwark has never offered hosted
scanning -- the self-host page says so explicitly. Week 53's own pre-Phase-13 gate (§39.5) makes it
a real one: "ADR-015 is implemented: the hosted deployment no longer runs Semgrep-maintained rules"
is a precondition for starting v3's multi-tenant, ingest-anything platform work, since that work is
explicitly heading toward a shape a hosted deployment could someday actually run.

## Decision

A new `Settings.hosted_mode` flag (`BULWARK_HOSTED_MODE`, default off -- nothing about today's
self-host deployment changes). When set:

- The default SAST tool becomes **Opengrep** (`HOSTED_DEFAULT_TOOLS` in `core/scan.py`) instead of
  Semgrep.
- An **explicit** request for `"semgrep"` (`POST /scans`, `/scans/upload`, or a GitHub App
  pull-request scan) is refused with a `422` naming the reason and the alternative, not silently
  substituted -- an operator should never be surprised about which tool actually ran.

Opengrep ([github.com/opengrep/opengrep](https://github.com/opengrep/opengrep)) is a
community-maintained, LGPL-2.1 fork of the Semgrep engine with no such restriction. Verified
directly, not assumed from its own marketing: its engine repository's `LICENSE` is plain LGPL-2.1,
confirmed by fetching it.

### The rules still needed solving separately

Opengrep's own bundled ruleset, `github.com/opengrep/opengrep-rules`, is **not** a safe substitute
for Semgrep's rules just because the engine is clear: its `LICENSE` file (fetched and read, not
assumed) adds a **Commons Clause** condition on top of its own LGPL-2.1 -- "the License does not
grant ... the right to Sell the Software," where "Sell" is explicitly defined to include "a product
or service whose value derives ... from the functionality of the Software," i.e. exactly offering it
as a hosted service. This is the same restriction, differently packaged, as Semgrep's own rules
license. The plan's own wording ("Opengrep **with the project's own rules**") turns out to be
load-bearing, not a stylistic choice: the engine alone does not solve the licensing problem.

`docker/opengrep/rules/` is therefore a small, originally-written starter ruleset (7 Python rules,
4 JavaScript/TypeScript rules), Apache-2.0 licensed under this project's own license
(`docker/opengrep/rules/LICENSE` states this explicitly), covering the same high-confidence patterns
`core/precommit/sast_scan.py`'s own AST-based checks already cover for the pre-commit hook (eval/
exec, shell=True, weak hashes, unsafe deserialization, disabled TLS verification) -- the same
underlying security judgment, expressed as Semgrep/Opengrep-syntax YAML instead of Python `ast`
walks, for a different execution context.

### No official Docker image; one real packaging problem to solve

Opengrep ships signed platform binaries via GitHub Releases, not a container image. Unlike every
other adapter's image (which pulls or lightly wraps an upstream image), `docker/opengrep/Dockerfile`
downloads the pinned `v1.30.0` binary for the target architecture and verifies it against a sha256
**obtained by downloading and hashing it directly**, not copied from a third party's claim (an
earlier search surfaced a plausible-looking but nonexistent `ghcr.io/opengrep/opengrep` and
`opengrep/opengrep` Docker Hub image; both were checked against the registries' own APIs and found
not to exist before this Dockerfile was written around the real distribution mechanism instead).

### A real sandbox incompatibility, found and fixed live

Opengrep's binary self-extracts a child `opengrep-core` executable and executes it from a temp
directory. The sandbox's shared `/tmp` is a `noexec` tmpfs for every adapter
(`core.sandbox.docker_runtime`) -- confirmed live, this fails every single Opengrep run with
"couldn't launch child (exec): Permission denied" (and, before raising `tmp_size` from the default
64m, "couldn't unpack file to target path: No space left on device"). The fix is *not* to loosen the
shared `/tmp` protection (tried and reverted -- it would weaken every other adapter's sandbox for one
tool's sake, and on investigation turned out not to be the real cause of the exec failure anyway: a
bare, unrestricted `--tmpfs=/tmp` mount with no flags at all still failed the identical way, which a
totally unmounted default `/tmp` did not). `docker/opengrep/Dockerfile` instead points
`HOME`/`TMPDIR` at `/scratch`, a plain writable Docker volume (the same `ToolSpec.writable_volumes`
mechanism Trivy already uses for its own `/db`) -- not tmpfs, so not `noexec`. `/tmp` itself stays
exactly as restrictive as it is for every other tool.

## Consequences

- Hosted mode's SAST coverage is intentionally narrower than self-host's: 11 original rules across
  2 languages versus Semgrep's full community ruleset across 4+. This is the stated trade-off, not
  an oversight -- growing `docker/opengrep/rules/` is future, incremental, low-risk work (add a
  rule, add a golden-fixture case), not a blocker to this decision.
- `core/adapters/opengrep.py` is registered in `core/scan.py`'s `ADAPTERS` (selectable by name in
  self-host mode too, for testing or by choice) but not in self-host's own `DEFAULT_TOOLS` --
  self-host keeps getting Semgrep by default, unchanged.
- Severity normalization reuses Semgrep's own `ERROR`/`WARNING`/`INFO` -> `HIGH`/`MEDIUM`/`LOW`
  mapping (`core/scoring/severity.py`): same engine lineage, same vocabulary.
- `BULWARK_HOSTED_MODE` is the only new operator-facing setting; nothing about an existing self-host
  deployment's behavior, defaults, or `.env` changes.

## What is NOT done

- The starter ruleset is deliberately small (Python + JavaScript/TypeScript only -- no Go, Java,
  Terraform, or Dockerfile rules yet, all of which Semgrep's own default set covers for self-host).
- No precision/recall measurement of the new ruleset against a labelled corpus (the same disclosed
  gap `docs/evaluation-v2.md` already names for several other v2 features) -- each rule was
  hand-verified against a real true/false-positive pair while building it (`docker/opengrep/rules/`
  commit's own verification record), not measured at corpus scale.
- `BULWARK_HOSTED_MODE` gates tool *selection* only. Nothing else about running Bulwark as a genuine
  multi-tenant hosted service (billing, per-tenant resource isolation beyond the existing RLS/
  sandbox boundaries, a terms-of-service/abuse policy) is addressed by this decision -- it closes
  exactly the one gate item the plan named before Phase 13, nothing more.
