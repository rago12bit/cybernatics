# Policy-as-code (plan §20.4)

A severity threshold (`--fail-on high`) can't express "no secrets, ever" or "an accepted risk
expires after 90 days" — rules that aren't about severity at all. A policy can. Bulwark embeds
[Open Policy Agent](https://www.openpolicyagent.org/) and evaluates a Rego policy's
`data.gate.pull_request.deny` rule against every scan, alongside (not instead of) the severity
threshold.

## Installing `opa`

A single static binary, no package manager needed:

```bash
curl -sL -o /usr/local/bin/opa \
  https://openpolicyagent.org/downloads/v1.21.0/opa_$(uname -s | tr '[:upper:]' '[:lower:]')_amd64_static
chmod +x /usr/local/bin/opa
opa version
```

(Apple Silicon: replace `amd64` with `arm64`.) Without `opa` on `PATH`, `--policy` isn't usable and
`core.policy`'s own tests are skipped automatically — nothing else in Bulwark needs it.

## Using a policy

```bash
bulwark ci compare --head head.json --base base.json --fail-on high --policy gate.rego
```

The check fails if the severity threshold is breached **or** the policy denies anything — either
one can fail it, neither can override the other. In the GitHub Action, set `policy-file` to a path
in your repository (e.g. `.bulwark/gate.rego`); OPA is only downloaded when this is set.

## Writing a policy

Start from the bundled starter library (`core/policy/starter/gate.rego`) — copy it, keep what you
want, delete or add rules. Every rule is its own `deny contains msg if { ... }` block; Rego unions
same-named rules automatically, so you don't need `or`.

```rego
package gate.pull_request

deny contains msg if {
    some issue in input.new_issues
    issue.in_cisa_kev
    issue.reachable
    msg := sprintf("%s is actively exploited and reachable from %s", [issue.id, issue.entrypoint])
}
```

`input.new_issues` is a list of objects built from the scan's own findings
(`core/policy/input.py::issue_document`) — the exact fields available:

| Field | Always present? | Source |
|---|---|---|
| `id`, `fingerprint`, `title` | yes | the finding itself |
| `severity` | yes | `HIGH`/`MEDIUM`/... (uppercase) |
| `category` | yes | `sast`, `sca`, `secrets`, `iac`, `container` |
| `cwe`, `owasp` | yes (may be empty) | the finding's taxonomy |
| `in_cisa_kev` | yes | `false` unless the finding's CVE is in CISA KEV |
| `malicious` | yes | `false` unless osv-scanner matched an OSSF malicious-packages report (a `MAL-` id, plan §20.5) |
| `risk_score` | yes (may be `null`) | the same 0–100 score the UI shows |
| `entrypoint` | yes (may be `""`) | the real HTTP entrypoint a taint path (plan §20.3) traced back to, if any |
| `reachable` | **only when known** | Week 37/38's taint analysis, or import-level SCA reachability — absent, not `null`, when unknown |
| `license` | **only with `--sbom`** | joined from a CycloneDX SBOM's own package licenses (plan §20.5) — see "Supply-chain risk" below |
| `triage_status`, `triage_expires_at` | **only in the hosted pipeline** | a database-backed `IssueRow`; the standalone CLI/Action never has this |

Test your policy the same way the starter library is tested:

```bash
opa test path/to/your/policy/
```

`bulwark ci compare` also runs `opa check` on your policy before evaluating it — a syntactically
invalid policy exits 2 (a real error), never a silent pass.

## Supply-chain risk (plan §20.5)

Malicious-package detection needs no extra step: `bulwark scan`'s own osv-scanner already checks
every dependency against OSV, whose database includes OSSF's malicious-packages reports (`MAL-`
ids) alongside ordinary CVEs. Such a finding is always `CRITICAL` severity and `malicious: true` in
policy input, regardless of what (if any) severity label the record itself carries.

License policy needs one extra step, since license data lives in an SBOM, not a scan:

```bash
bulwark sbom . --output sbom.cdx.json
bulwark ci compare --head head.json --policy gate.rego --sbom sbom.cdx.json
```

`--sbom` joins each finding's package onto the SBOM's own declared license (matched by ecosystem,
name and version) before policy evaluation — nothing is guessed for a package the SBOM has no
license for, and `--sbom` has no effect without `--policy`. In the GitHub Action, set `sbom: true`;
the SBOM step already runs before the gate for exactly this reason.

Typosquat detection and OpenSSF Scorecard for direct dependencies are their own command, since
neither is about deny/allow policy — they run over an SBOM directly and produce a JSON report,
not policy denials:

```bash
bulwark supply-chain analyze --sbom sbom.cdx.json --output supply-chain.json
```

This flags a package name within edit distance 1–2 of a well-known package in the same ecosystem
(a small, hand-curated seed list — not a live popularity feed), and fetches each *direct*
dependency's [OpenSSF Scorecard](https://scorecard.dev) result via deps.dev and
api.securityscorecards.dev, cached for a week. Pass `--no-scorecard` to skip the network calls.

## What this isn't (yet)

- **No policy editor UI.** Write the `.rego` file by hand, in your own editor, and commit it — the
  plan's own Monaco-based live-evaluation editor (§28.6) is deferred (ADR-0023).
- **No org-level saved policy.** A policy lives in your repository as a file today, not in
  Bulwark's own database.
- **OPA runs unsandboxed**, deliberately: it evaluates data this platform already computed (a
  scan's own findings), never the scanned repository's own content, so there's nothing here for the
  sandboxed scanner runner to protect against.
- **The Dependencies screen needs a hosted scan, not just the CLI.** Opt a hosted scan into `"syft"`
  (the web UI's own scan-creation form has a checkbox for it) to populate `/app/projects/{id}/
  dependencies`; the standalone `bulwark supply-chain analyze` report is still there for the
  CLI/Action path, which has no persisted screen to render into (ADR-0025).
- **Direct-versus-transitive needs a lockfile.** Syft's own `dependencies` graph is only as complete
  as the manifest format it read: a committed lockfile (`package-lock.json`, `poetry.lock`,
  `Cargo.lock`, ...) has the resolved tree; a bare, unlocked manifest does not, so `direct_purls`/
  `transitive_purls` are simply empty for it — absent data, not a fabricated "everything is direct".
