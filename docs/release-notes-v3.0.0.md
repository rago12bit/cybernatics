# Bulwark 3.0.0 — release notes

Released 2026-10-08, with 2.5.0 the same day.

> **Released without the third usability study.** The plan tags `v3.0.0` after milestone M16,
> whose study needs five security leads or pen testers; it has not run
> ([ux-study.md](ux-study.md)), and both tags were cut at the owner's decision without it. The tag
> also starts the release workflow, which publishes signed images; no run of it has been observed
> from here. Every change since 2.4.0 is in [CHANGELOG.md](https://github.com/Rag2102/cyberimp/blob/main/CHANGELOG.md), under 2.5.0 and 3.0.0.

Version 2 found vulnerabilities, ranked them and helped fix them. Version 3 (Weeks 53–78) manages
them, alongside the tools a team already uses. The write-up is [blog-v3.0.0.md](blog-v3.0.0.md); the
numbers, including the ones that don't flatter, are [evaluation-v3.md](evaluation-v3.md).

## Highlights

**Bring in what you don't scan yourself.** One import endpoint for SARIF, CycloneDX, SPDX, OSV and ten
formats ported from DefectDojo (ZAP, Nuclei, Burp, Nessus, OpenVAS, Grype, Trivy, Snyk, GitLab, Checkov),
plus a universal mapper for anything else. Every report is parsed in a sandbox, previewed as new,
unchanged, reopened and closed before anything is saved, and reimported without closing what it
didn't look at. Connectors pull from DefectDojo and other tools on a schedule; deduplication can be set
per source, with a dry run. (2.1.0–2.2.0)

**Run the program.** Portfolios, projects, engagements and tests. SLAs from first detection;
risk acceptance that needs a second person and expires; a priority engine you can weight;
pen-test engagements with manual findings (CVSS 4.0), checklists, retests and a report at close.
(2.3.0)

**Automate the routine.** A rules engine (Rego, with a dry run over the last seven days),
notifications, two-way tickets with Jira and GitHub Issues, and a calendar. (2.4.0)

**Know what you run.** An SBOM inventory per project, advisory matching with OSV's semantics (checked
against osv-scanner: 99.5% agreement, never missing one it finds), and VEX drafted from call-graph
evidence that a person confirms. Compliance mappings and signed evidence packs an auditor can check.
(2.4.0)

**See it.** A metrics layer, dashboards with a keyboard alternative to drag-and-drop, role homes, a
report builder with signed PDFs and schedules, and filters, saved views and bulk changes that work across
every project. (2.5.0)

**Who and how.** OIDC and SAML sign-in, SCIM, organization roles with per-portfolio and per-project
overrides enforced by Postgres row-level security, personal API tokens. An MCP server so your own agent
can ask Bulwark as you, read-only by default, with scanned text labelled as untrusted; `/fix` on pull
requests, previewed with its cost and never run for a fork. A public website with a recorded scan of
OWASP Juice Shop and a generated integrations catalogue. (3.0.0)

## Upgrading from 2.x

- Migrations run in order to `0050`; run `alembic upgrade head` as the table-owning role, as before.
- New settings are optional and listed in the docs they belong to: single sign-on
  ([identity.md](identity.md)), connectors, the advisory feeds, `/fix`
  ([fix-on-pull-requests.md](fix-on-pull-requests.md)), the MCP server ([mcp.md](mcp.md)).
- The GitHub App needs the **Issue comment** event for `/fix` ([github-app.md](github-app.md)).
- Tokens made before accounts keep working with their scopes.

## Known limits

- **Not measured:** deduplication accuracy, the blind review of VEX proposals, and the usability study
  (SUS and time on task for J6–J10). Each is in evaluation-v3.md with the reason.
- **No real model has run** the verified-fix agent or `/fix`: patch quality is unmeasured.
- `/fix` has not been exercised with a real GitHub App delivering real comments.
- The rules engine's p95 is for one evaluation, not the plan's load test.
- The release workflow's signing and provenance have not been observed on a real run.

The full list of what is proven and what isn't, week by week, is in `docs/v2-week*-verification.md`.
