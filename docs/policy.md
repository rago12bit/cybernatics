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
| `risk_score` | yes (may be `null`) | the same 0–100 score the UI shows |
| `entrypoint` | yes (may be `""`) | the real HTTP entrypoint a taint path (plan §20.3) traced back to, if any |
| `reachable` | **only when known** | Week 37/38's taint analysis, or import-level SCA reachability — absent, not `null`, when unknown |
| `license` | **not yet** | needs Week 40's SBOM/license work; the starter library's license rule is real, tested Rego with nothing to match against today |
| `triage_status`, `triage_expires_at` | **only in the hosted pipeline** | a database-backed `IssueRow`; the standalone CLI/Action never has this |

Test your policy the same way the starter library is tested:

```bash
opa test path/to/your/policy/
```

`bulwark ci compare` also runs `opa check` on your policy before evaluating it — a syntactically
invalid policy exits 2 (a real error), never a silent pass.

## What this isn't (yet)

- **No policy editor UI.** Write the `.rego` file by hand, in your own editor, and commit it — the
  plan's own Monaco-based live-evaluation editor (§28.6) is deferred (ADR-0023).
- **No org-level saved policy.** A policy lives in your repository as a file today, not in
  Bulwark's own database.
- **OPA runs unsandboxed**, deliberately: it evaluates data this platform already computed (a
  scan's own findings), never the scanned repository's own content, so there's nothing here for the
  sandboxed scanner runner to protect against.
