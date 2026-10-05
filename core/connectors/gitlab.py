"""GitLab vulnerability reports (plan §42.5), pulled through GitLab's GraphQL API -- the supported
interface for a project's vulnerability report (the REST vulnerability endpoints are deprecated).

Needs a token with the `read_api` scope from an account that can see the project's vulnerability
report (GitLab Ultimate). Only `DETECTED` and `CONFIRMED` vulnerabilities are pulled: a dismissed or
resolved one is no longer on the list, so reimport closes it here too.

Each GraphQL node is turned into the shape of a record in a GitLab security report and read by
`core.imports.parsers.gitlab.vulnerability_finding` -- the function an uploaded `gl-*-report.json`
is read with -- so a pulled vulnerability and an uploaded one cannot disagree about what it is.
The query was checked field by field against gitlab.com's published GraphQL schema on 2026-10-05
(`tests/golden/connectors/gitlab-schema-extract.json`).
"""

from __future__ import annotations

import json
from typing import Any

from core.connectors.base import MAX_PAGES, PER_PAGE, Fetched
from core.connectors.http import ConnectorError, Transport, expect_ok
from core.imports.parsers.base import ParseContext
from core.imports.parsers.gitlab import vulnerability_finding

QUERY = """
query BulwarkVulnerabilities($fullPath: ID!, $after: String, $first: Int!) {
  project(fullPath: $fullPath) {
    id
    vulnerabilities(state: [DETECTED, CONFIRMED], first: $first, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        id
        title
        description
        solution
        severity
        reportType
        state
        webUrl
        identifiers { externalType externalId name url }
        links { url }
        scanner { name vendor }
        location {
          __typename
          ... on VulnerabilityLocationSast { file startLine endLine }
          ... on VulnerabilityLocationSecretDetection { file startLine endLine }
          ... on VulnerabilityLocationDependencyScanning {
            file
            dependency { version package { name } }
          }
          ... on VulnerabilityLocationContainerScanning {
            image
            operatingSystem
            dependency { version package { name } }
          }
          ... on VulnerabilityLocationDast { hostname path requestMethod param }
        }
      }
    }
  }
}
""".strip()

_REPORT_TYPE = {
    "SAST": "sast",
    "DEPENDENCY_SCANNING": "dependency_scanning",
    "CONTAINER_SCANNING": "container_scanning",
    "SECRET_DETECTION": "secret_detection",
    "DAST": "dast",
    "API_FUZZING": "api_fuzzing",
    "COVERAGE_FUZZING": "coverage_fuzzing",
    "CLUSTER_IMAGE_SCANNING": "cluster_image_scanning",
    "GENERIC": "generic",
}


def as_report_record(node: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """A GraphQL vulnerability node -> (a security-report record, its scan block)."""
    loc = node.get("location") or {}
    dep = loc.get("dependency") or {}
    location: dict[str, Any] = {
        "file": loc.get("file"),
        "start_line": loc.get("startLine"),
        "end_line": loc.get("endLine"),
        "image": loc.get("image"),
        "operating_system": loc.get("operatingSystem"),
        "hostname": loc.get("hostname"),
        "path": loc.get("path"),
        "method": loc.get("requestMethod"),
        "param": loc.get("param"),
    }
    if dep:
        location["dependency"] = {
            "package": {"name": ((dep.get("package") or {}).get("name"))},
            "version": dep.get("version"),
        }
    record = {
        "id": str(node.get("id") or ""),
        "name": node.get("title"),
        "description": node.get("description"),
        "solution": node.get("solution"),
        "severity": str(node.get("severity") or "Unknown").title(),
        "identifiers": [
            {
                "type": str(i.get("externalType") or "").lower(),
                "name": i.get("name"),
                "value": i.get("externalId"),
                "url": i.get("url"),
            }
            for i in node.get("identifiers") or []
            if isinstance(i, dict)
        ],
        "links": [{"url": u} for u in [node.get("webUrl")] if u]
        + [{"url": link.get("url")} for link in node.get("links") or [] if isinstance(link, dict)],
        "location": {k: v for k, v in location.items() if v is not None},
    }
    scanner = node.get("scanner") or {}
    scan = {
        "type": _REPORT_TYPE.get(str(node.get("reportType") or ""), "generic"),
        "scanner": str(scanner.get("name") or "gitlab"),
    }
    return record, scan


def fetch(transport: Transport, base_url: str, token: str, full_path: str) -> Fetched:
    url = f"{base_url.rstrip('/')}/api/graphql"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "bulwark-connector",
    }
    out = Fetched([], 0)
    ctx = ParseContext()
    skipped = 0
    after: str | None = None
    for n in range(1, MAX_PAGES + 2):
        if n > MAX_PAGES:
            raise ConnectorError(
                f"GitLab: more than {MAX_PAGES * PER_PAGE} vulnerabilities; "
                "refusing a partial pull"
            )
        body = json.dumps(
            {
                "query": QUERY,
                "variables": {"fullPath": full_path, "after": after, "first": PER_PAGE},
            }
        ).encode()
        data = expect_ok(transport("POST", url, headers, body), "GitLab")
        out.requests = n
        if not isinstance(data, dict):
            raise ConnectorError("GitLab: the response is not JSON")
        if data.get("errors"):
            first = data["errors"][0] if isinstance(data["errors"], list) else data["errors"]
            message = first.get("message") if isinstance(first, dict) else str(first)
            raise ConnectorError(f"GitLab: {message}")
        project = (data.get("data") or {}).get("project")
        if project is None:
            raise ConnectorError(
                f"GitLab: project {full_path!r} was not found, or the token cannot see it",
                auth=True,
            )
        conn = project.get("vulnerabilities")
        if conn is None:
            raise ConnectorError(
                "GitLab: the vulnerability report is not available for this project (it needs "
                "GitLab Ultimate, and a token whose user can see it)",
                auth=True,
            )
        for node in conn.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            out.items += 1
            record, scan = as_report_record(node)
            try:
                finding = vulnerability_finding(record, scan, {}, ctx)
            except (KeyError, TypeError, ValueError, AttributeError):
                finding = None
            if finding is None:
                skipped += 1
            else:
                out.findings.append(finding)
        info = conn.get("pageInfo") or {}
        if not conn.get("nodes") and info.get("hasNextPage"):
            # What gitlab.com really returns to a viewer who may not read the report: an empty
            # page that says there are more (seen 2026-10-05, tests/golden/connectors/). Paging on
            # would pull nothing a hundred times; it is a permissions problem, said as one.
            raise ConnectorError(
                "GitLab: the project has vulnerabilities this token's user is not allowed to see; "
                "it needs at least the Developer role (and GitLab Ultimate)",
                auth=True,
            )
        if not info.get("hasNextPage"):
            break
        after = info.get("endCursor")
        if not after:
            raise ConnectorError("GitLab: a next page with no cursor; refusing a partial pull")
    if skipped:
        out.warnings.append(f"{skipped} vulnerability(ies) had no usable location and were skipped")
    for label, count in ctx.unknown_severities.items():
        out.warnings.append(
            f"{count} vulnerability(ies) have the severity {label!r}; imported as Info"
        )
    return out
