# Bulwark v2.0.0

Weeks 27-52 of the plan, Milestone M11: "v2.0 public launch." v1.0.0 was a sandboxed multi-scanner
pipeline that found, correlated and ranked vulnerabilities. v2.0.0 turns that into a platform: stable
issue identity across scans, multi-tenancy, an LLM-backed analysis layer that proposes and verifies
real fixes, hardened-by-default infrastructure, authorized DAST, and a plugin/integrations ecosystem
around it. Full detail for every line below is in [CHANGELOG.md](https://github.com/rago12bit/cybernatics/blob/main/CHANGELOG.md); the honest numbers
are in [docs/evaluation-v2.md](evaluation-v2.md).

## Platform foundations (Phase 7, weeks 27-30 -> `v1.1.0`)

- **Stable issue identity.** A finding used to be a new row every scan; an `Issue`/`Occurrence` split
  (ADR-0012) now tracks one real vulnerability across scans with a location-independent fallback
  fingerprint, so "new", "fixed" and "returned" are real states, not a guess from diffing reports.
- **Multi-tenancy, for real.** Organizations, projects, roles, and Postgres Row-Level Security with
  `FORCE ROW LEVEL SECURITY` on every tenant table (ADR-0013) -- not an application-level `WHERE
  org_id = ...` a future query could forget. An automated two-tenant leak test runs on every
  endpoint, on every pull request.
- **A GitHub App** replaces the OAuth app; scoped, hashed, prefixed API tokens; a hash-chained,
  tamper-evident audit log with signed checkpoints published to Sigstore's Rekor.

## UX overhaul (Phase 8, weeks 31-35)

- A heuristic evaluation and journey maps against the real v1 UI (the actual baseline usability
  study with real participants is still pending real participant recruitment -- disclosed, not
  faked).
- A real design system: tokens, severity shapes, Radix primitives, Storybook.
- The app shell, project overview (opens with a verdict sentence, not a stats block), a virtualized
  issues table with keyboard triage, onboarding, empty/error states, and an accessibility pass.

## Advanced analysis engine (Phase 9, weeks 36-40 -> `v1.3.0`)

- **Incremental scanning**: a content-addressed result cache turns an unchanged-file rescan into a
  cache hit -- 3.6x faster on a real warm PR scan ([measured](evaluation-v2.md)).
- **Code intelligence and taint analysis**: a real call graph (Python/JS/Go, tree-sitter-based) and
  a taint engine that confirms whether a SAST finding is actually reachable from a real HTTP
  entrypoint -- attached to Issues and fed into risk scoring and the UI as a step-by-step path.
- **Policy-as-code**: Open Policy Agent evaluates a Rego policy's `deny` rules alongside the severity
  threshold -- "no secrets, ever" and "an accepted risk expires after 90 days" are rules a threshold
  alone can't express.
- **Supply-chain risk**: malicious-package detection (OSSF `MAL-` ids via OSV), typosquat detection,
  and OpenSSF Scorecard for direct dependencies.

## LLM intelligence (Phase 10, weeks 41-45)

- **A model gateway** (ADR-0026): a real local backend option, caching, and budgets -- not locked to
  one hosted provider.
- **The verified-fix agent** -- "the flagship v2 feature": proposes a patch, reruns the triggering
  rule, reruns every scanner, runs the project's own tests, and only then offers it for human
  approval, as a real GitHub PR.
- **Triage assistant and Hypotheses lane**: an LLM verdict on "likely false positive", and a
  deterministic-candidate-generation + LLM-verdict lane for authorization flaws pattern matching
  can't express on its own.
- **Security copilot**: tool-grounded chat scoped to one project, never another tenant's data.
- **Attack paths, a threat model draft, and an LLM red-team suite**: 20 adversarial payloads against
  every contract that parses raw model text, run in CI on every push.

## Platform security and DAST (Phase 11, weeks 46-49b -> `v1.5.0`)

- A pluggable `SandboxRuntime` interface with a gVisor backend and egress denial for fix
  verification; envelope encryption via OpenBao with per-scan data keys and crypto-shredding; mTLS
  between every internal service.
- Nightly fuzzing of every parser, a full OWASP ASVS 4.0.3 Level 2 self-assessment, SLSA Level 3
  provenance and signed images.
- **Authorized DAST**: ownership verification before a URL can ever be scanned, a scope-enforcing
  egress proxy wired into real campaign execution (not just configured), ZAP/Nuclei behind rate
  limits and time windows, and SAST/DAST correlation ("confirmed at runtime").

## Scale, ecosystem, and launch (Phase 12, weeks 50-52 -> `v2.0.0`)

- **Scale**: a Helm chart with KEDA autoscaling on real Celery queue depth (1 to 5 replicas on a real
  3,000-task backlog, drained in under 30s on a real `kind` cluster), k6 load tests that found and
  drove the fix for two genuine capacity bugs, and a cost-per-scan dashboard.
- **Ecosystem**: a Plugin SDK (entry-point discovery, a shared conformance kit, keyless Sigstore
  signing re-verified on every use); Slack/Discord/GitHub Issues/Jira integrations with asymmetric
  two-way sync; a native, no-Docker pre-commit hook; a real MkDocs Material documentation site.
- **Launch**: [docs/evaluation-v2.md](evaluation-v2.md) (the honest numbers, including what still
  needs a live model to measure), this landing page you're reading about -- its first screen is now
  a replay of a real scan of OWASP Juice Shop, not a stats block -- and this release.

## What v2.0.0 is honest about not having yet

- **No real, human-measured usability improvement.** The UX overhaul shipped real screens on a real
  design system; the before/after SUS study that would prove it's actually more usable needs real
  participants, not fabricated data, and hasn't been run.
- **Five evaluation areas need a live LLM to measure**: verified-fix acceptance rate and blind human
  review, triage assistant and hypotheses-lane precision/recall, Copilot's citation accuracy, and a
  real attack-success-rate (as opposed to the structural-defense pass rate that *is* measured) for
  the red-team suite. Every one of these is disclosed in its own week's verification doc.
- **Still a single shared bearer token for API auth outside the GitHub App flow** -- no per-user
  identity yet; that's v3's Part 6 ("Identity, AI v3, Launch").
- **Taint analysis, risk ranking, and the LLM layer are all still disclosed-scope-cut, judgment-call
  systems**, not formally verified ones -- see each feature's own ADR for exactly where the lines
  are drawn.

## Upgrading

No breaking API changes from `v1.x` to `v2.0.0`'s `/v1` surface; the `/v2` endpoints added since Week
28 are additive. Database migrations run automatically (`alembic upgrade head` in the `migrate` job
for Helm, or on worker start for Compose). See [helm/bulwark/README.md](https://github.com/rago12bit/cybernatics/blob/main/helm/bulwark/README.md) or
the [Quickstart](quickstart.md) for either deployment path.
