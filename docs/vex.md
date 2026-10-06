# VEX: telling customers which vulnerabilities do not affect them

A VEX document (Vulnerability Exploitability eXchange) goes with an SBOM: for each vulnerability in
the product's components, it says whether the product is affected, and if not, why. Bulwark writes a
project's VEX from what the organization has decided, as [OpenVEX](https://github.com/openvex/spec)
v0.2.0 or CycloneDX 1.6 VEX. The design is [ADR-0053](adr/0053-vex-compliance-evidence.md).

## Where statements come from

For every vulnerability the [advisory engine](adr/0052-advisory-engine.md) finds in the project's
current SBOM, at every library version:

| What the organization decided | Exported as |
|---|---|
| A person confirmed a VEX statement | `not_affected`, its justification, the evidence and its limits, who confirmed it |
| The dependency Issue was marked not a risk | `not_affected`, with the justification chosen (or the reason, if none was) |
| Nothing, and the version matches | `affected`, with the fix ("Upgrade x to 1.2.3 or later") |
| Nothing, and the version could not be compared | `under_investigation` |
| A confirmed statement the latest scan contradicts | `under_investigation`, saying so |

Only PyPI, npm, Go and Maven vulnerabilities are included (what the advisory engine covers).

## Marking a dependency Issue not a risk

On a dependency Issue, "Mark as not a risk" offers OpenVEX's five justifications:

| OpenVEX | CycloneDX | Meaning |
|---|---|---|
| `component_not_present` | `code_not_present` | The vulnerable component is not in the product |
| `vulnerable_code_not_present` | `code_not_present` | The component is there, but not its vulnerable code |
| `vulnerable_code_not_in_execute_path` | `code_not_reachable` | The vulnerable code is never executed |
| `vulnerable_code_cannot_be_controlled_by_adversary` | `requires_environment` | An attacker cannot control the vulnerable code's input |
| `inline_mitigations_already_exist` | `protected_by_mitigating_control` | Built-in protections already stop it |

The CycloneDX column is Bulwark's mapping (neither specification defines one); CycloneDX
statements also carry the OpenVEX value in `bulwark:openvex:justification`.

## Draft VEX for the others

On an advisory's page, **Draft VEX** proposes `not_affected` / `vulnerable_code_not_in_execute_path`
for each use where Bulwark has evidence, and nothing where it has none. Two kinds of evidence:

- **Vulnerable functions not called (Go).** Go's vulnerability database names the vulnerable
  functions. When Bulwark scans a project it reads its Go source (parsed, never built or run) and
  records which names the code uses from each package it imports, and every method name it calls.
  If none of the vulnerable functions is used, the use is proposed. Matching is by name and errs
  towards "used": any call of a method called `Next` counts as a call of `Tokenizer.Next`.
- **Package not imported (Python, JavaScript, and Go records that name no functions).** The package
  is a declared dependency no application source file imports, or only tests do.

Nothing is proposed for Maven packages, versions that could not be compared, malicious packages, or
projects Bulwark has not scanned (an imported SBOM has no source to read).

**What the evidence does not cover**, and every statement says so:

- Code inside other dependencies is not analysed. If another library calls the vulnerable function
  on the project's behalf, the claim is wrong.
- Calls through reflection, plugins or function values obtained elsewhere are not seen.
- Import-level evidence does not know which functions are vulnerable.

A proposal is exported nowhere until a person confirms it, with their own API token. Confirming also
marks the matching Issue not a risk with the same justification; reopening that Issue withdraws the
statement. Rejected proposals are not proposed again until a scan changes the evidence. Every step
is in the audit log.

## Downloading

On the project's **VEX** page, or:

    GET /v2/projects/{id}/vex/openvex
    GET /v2/projects/{id}/vex/cyclonedx

The product is identified by the project's repository URL (or a `urn:uuid:` for other projects),
each component by its package URL. The documents validate against the OpenVEX v0.2.0 and CycloneDX
1.6 JSON schemas, and `vexctl filter` applies them to SARIF results.

## How good are the proposals?

Not yet measured. The plan asks for 100 proposals reviewed blind; `scripts/vex-review-kit.py` makes
the review sheet (proposals mixed with uses that were not proposed, Bulwark's answer hidden) and
scores the answers. It needs a reviewer and real projects.
