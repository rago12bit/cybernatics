# ADR-0053: VEX drafted from code evidence and confirmed by a person; compliance as cited data; evidence an auditor can check

Status: Accepted (2026-10-06), Week 69 (plan §46.3, §47, §55.5). Builds on
[ADR-0052](0052-advisory-engine.md) (advisories and impacts), [ADR-0019](0019-tamper-evident-audit-log.md)
(the audit log and its Rekor checkpoints) and [ADR-0046](0046-sla-and-risk-acceptance.md) (SLAs and risk acceptance).

## Context

Plan §46.3: record why a dependency Issue is "not a risk" in OpenVEX's vocabulary, export OpenVEX and
CycloneDX VEX, and propose `vulnerable_code_not_in_execute_path` "with the call-graph evidence
attached, and a person confirms it". §47: mappings as versioned data that cite their source, an ASVS
benchmark per project, and an evidence pack whose audit-log extract an auditor "can check instead of
trust". M15: "VEX exports carry call-graph evidence."

## Decision

**What the evidence can be.** Only Go's vulnerability database names the vulnerable functions
(931 of OSV's Go records; none of its PyPI, npm or Maven records). So there are two kinds of
evidence, and they are labelled as different things:

- *symbols* (Go): at scan time Bulwark parses the project's Go source (tree-sitter; never built or
  run) and keeps, per imported package, the names the code uses from it, and every method or field
  name it selects anywhere (`code_usage`). A Go vulnerability is proposed as not in the execute path
  when no vulnerable function of any affected package is referred to. Matching is by name and
  deliberately over-inclusive -- any `.Next(` counts as a call of `Tokenizer.Next`, a dot-import's
  bare names count, a local variable named like a package counts -- because a false "not executed"
  is the error that matters. An import whose bound name cannot be told from its path (Go rejects
  unused imports, so no candidate being used means the name is unknown) makes the answer "can't
  tell".
- *imports* (Python, JavaScript, and Go records naming no functions): reachability v1 says the
  package is declared but not imported by application code, or only by tests.

"Call-graph evidence" in the plan is therefore, for Go, use of the vulnerable functions in the
application's own code; neither kind follows calls into other dependencies, and both say so in the
statement. No evidence, no proposal: Maven, uncertain versions, malicious packages (their code runs
at install), projects never scanned by Bulwark.

**A proposal is not a claim.** "Draft VEX for the others" writes `vex_statements` in state
`proposed`; nothing is exported until a person confirms it, with a personal token (the shared token
could be anyone). Confirming marks the matching Issue not a risk with the justification; reopening
that Issue withdraws the statement. A rejected proposal is not proposed again until a later scan
changes the evidence. Every step is audit-logged.

**Exports.** One statement per vulnerability per library version in the project's current SBOM: a
confirmed statement (`not_affected`, its justification, the evidence and its limits in
`impact_statement`, who confirmed it), else an Issue dismissed with a justification (or with only a
reason, exported as the impact statement), else `affected` with the fix, or `under_investigation`
when the version could not be compared. A confirmed statement the latest scan contradicts is
exported as `under_investigation`, never as still true. OpenVEX v0.2.0 and CycloneDX 1.6; the
justification mapping is Bulwark's own (neither specification defines one), and CycloneDX statements
keep the OpenVEX value and the evidence in properties.

**Compliance as cited data.** One file per framework in `core/compliance/frameworks/`, each with its
source, version, terms and a mapping version; each control maps to kinds of evidence Bulwark holds.
OWASP Top 10 and ASVS reuse OWASP's own data already shipped (CC BY-SA 4.0). PCI DSS, ISO 27001 and
SOC 2 are copyrighted: requirement numbers and Bulwark's paraphrases only. Every surface says a
mapping is not a certification.

**ASVS: only a person says "met".** Without a person's status a requirement shows what the evidence
shows -- failed in an assessment, open Issues of its CWE, passed an assessment ("tested", not
"met"), or not assessed. The absence of findings is never shown as a control working. A person's
"met" that the evidence contradicts is flagged.

**The audit log becomes per-organization without being split.** It stays one chain (a split would
need a re-hash of history). Version-2 entries (migration 0041 onwards) put the organization inside
the hash through a body digest: `entry_hash = SHA256("2"|seq|prev_hash|body_digest)`, `body_digest =
SHA256(canonical JSON of timestamp, org, actor, action, target, payload digest)`. An organization's
extract shows its own entries in full and everyone else's as `(seq, prev_hash, body_digest,
entry_hash)`: every hash is recomputed, nothing of another organization is revealed but that an
entry exists. Version-1 entries (no organization recorded) are shown as hashes and can only be
checked by link.

**Evidence packs.** A zip: the PDF, `evidence.json`, the audit extract (reaching to the first Rekor
checkpoint after the period, so the period is anchored when one exists), each checkpoint's Sigstore
bundle, `verify.py` (standard library only: manifest hashes, the chain, the checkpoints' positions)
and `manifest.json`, signed with the deployment's cosign key when `BULWARK_EVIDENCE_SIGNING_KEY` is
set; marked unsigned otherwise, and never produced unsigned when signing was asked for and failed.
Checkpoints can go to a private Rekor (`--rekor-url`) and be verified offline against its trusted
root.

## Consequences

- VEX proposals are only as good as name-based evidence in the application's own code; their
  precision is measured by the blind review the plan asks for (`scripts/vex-review-kit.py`), which
  needs a person and real projects and has not been done.
- Only vulnerabilities the advisory engine knows (PyPI, npm, Go, Maven) appear in exports.
- The audit chain's version-1 entries can never be attributed to an organization; extracts over them
  are weaker, and say so.
- Evidence packs are built in the request: 3 s for 100,000 Issues on a laptop; a deployment with
  millions of Issues needs them on the worker.
- Downgrading migration 0041 leaves version-2 entries that a version-1 verifier cannot check.
