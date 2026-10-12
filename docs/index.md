# Bulwark

**One scan, one deduplicated list of findings.** Bulwark runs five open-source security scanners
against a repository, merges what they agree on, and shows you a single list you can actually work
through.

Every scanner covers a different slice, so you run several, and then drown. A single SQL injection
shows up as a Bandit finding, a Semgrep finding and a CWE entry; one vulnerable npm package appears
in Trivy *and* OSV-Scanner, each with its own severity. Bulwark treats the pile as one problem:

1. **Run** [Bandit](https://github.com/PyCQA/bandit), [Semgrep CE](https://github.com/semgrep/semgrep),
   [Gitleaks](https://github.com/gitleaks/gitleaks), [Trivy](https://github.com/aquasecurity/trivy)
   and [OSV-Scanner](https://github.com/google/osv-scanner), each in a locked-down container.
2. **Normalize** every result into one `Finding` schema.
3. **Correlate**: merge duplicates across tools, keep every tool's evidence, take the highest
   severity.
4. **Map** each finding to its CWE and OWASP Top 10:2021 category.
5. **Rank** by risk: severity combined with EPSS and CISA's known-exploited list.
6. **Show and export** it: web UI, API, CLI, and downloadable SARIF, HTML and PDF reports.

## Where to go next

<div class="grid cards" markdown>

-   **[Quickstart](quickstart.md)**

    Get a scan running against your own code in a few minutes, either the full hosted stack
    (Docker Compose) or the standalone CLI.

-   **[Concepts](concepts/architecture.md)**

    How a scan actually works: the pipeline, the risk score, the vulnerability taxonomy, and what
    "reachable" means.

-   **[Writing a plugin](plugins.md)**

    Add a scanner Bulwark doesn't ship, as an ordinary installable Python package -- no fork
    required.

-   **[Policy cookbook](policy.md)**

    Write a Rego policy for rules severity thresholds can't express ("no secrets, ever", "an
    accepted risk expires after 90 days").

-   **[API reference](api.md)**

    Every endpoint, generated straight from the running app's own OpenAPI document -- never
    hand-maintained, never out of sync with it.

</div>

## Status

1.0.0. All 26 weeks of the original plan are done -- scanners, correlation, risk ranking,
LLM-backed fix suggestions, reachability, a VS Code extension and GitHub Action, SBOMs and signed
attestations -- and a second, larger plan (multi-tenancy, a plugin SDK, DAST, attack-path modeling,
and more) is in progress on top of it. Not ready for untrusted multi-user hosting yet: see
[Limits](https://github.com/rago12bit/cybernatics#limits) in the project README.

Source: <https://github.com/rago12bit/cybernatics>. License: Apache-2.0.
