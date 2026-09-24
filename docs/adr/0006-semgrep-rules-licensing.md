# ADR-006: Semgrep rules are fetched at build time and never redistributed

Status: Accepted (2026-09-24) — **needs a decision before the public demo (Week 10)**

## Context
The design document assumed Semgrep "community rules" were usable in a platform offering. In
practice the Semgrep *engine* is LGPL-2.1, but the `semgrep/semgrep-rules` repository is under the
**Semgrep Rules License v1.0**, which permits use "only for your own internal business purposes"
and does **not** allow distributing the rules or making them available to others as a service.
(Verified against semgrep.dev/legal/rules-license, 2026-09-24.)

## Decision
- Rules are never committed to this repo (`docker/semgrep/rules/` is git-ignored).
- `docker/semgrep/fetch-rules.sh` clones a pinned commit at image build time; each user builds
  their own image locally for their own use. The image is never pushed to a registry.
- The Semgrep adapter stays in the codebase: it is the reference for the shared SARIF path.

## Consequences
- Self-hosted / local CLI use: fine (internal use by the person who built the image).
- A **public hosted demo or SaaS** running these rules would violate the licence. Before Week 10,
  either (a) disable Semgrep on the hosted instance, (b) ship our own rules, or (c) evaluate a
  fork with permissively licensed rules, checking its rule licence separately, or (d) get legal
  advice / a commercial licence.
- `THIRD_PARTY_LICENSES.md` must record this distinction.
