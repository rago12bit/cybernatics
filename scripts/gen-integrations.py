#!/usr/bin/env python3
"""Generate web/lib/integrations.json, the public site's integrations catalogue (Week 77, plan §57:
"Integrations catalogue generated from parser and connector metadata").

Nothing here is typed by hand that the code already knows. Each entry is read from the registry
that decides what Bulwark actually does:

* scanners: `core.scan.ADAPTERS` (image, categories, languages; default or opt-in from
  `DEFAULT_TOOLS`) and the DAST campaign's tools (`core.dast.campaign.TOOLS_FOR_MODE`);
* imports: `core.imports.parsers.registry.PARSERS` (label, formats, categories, the default
  deduplication, and whether the parser was ported from DefectDojo), plus the universal mapper;
* connectors: `core.connectors.service.KINDS` (direction, credential, the permissions it needs);
* tickets: `core.tickets.config.PROVIDERS`; notifications: `core.notify.kinds`;
* agents (Week 76): the MCP server's tools (`core.mcp_server.server.offered_tools`) and `/fix` on
  pull requests (`core.fixagent.pr_command`).

The only hand-written text is a label and a one-line description for the few registries that carry
names alone (ticket providers, notification channels, DAST tools); `tests/unit/test_integrations.py`
fails when a registry gains an entry this file has no words for, and when the committed JSON differs
from what this script generates.

    python scripts/gen-integrations.py           # write web/lib/integrations.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "web" / "lib" / "integrations.json"

CATEGORY_LABELS = {
    "sast": "Code (SAST)",
    "secrets": "Secrets",
    "sca": "Dependencies (SCA)",
    "iac": "Infrastructure as code",
    "container": "Containers",
    "dast": "Running apps (DAST)",
    "network": "Network",
    "sbom": "SBOM",
}

# Registries that carry a name and nothing else. A new name with no words here fails the test.
DAST_TOOLS = {
    "zap-baseline": ("OWASP ZAP baseline", "Spiders and passively checks a verified web target."),
    "nuclei": ("Nuclei", "Template checks against a verified target; active campaigns only."),
}
TICKET_PROVIDERS = {
    "jira": ("Jira", "Tickets both ways: severity from Bulwark, status from the ticket."),
    "github": ("GitHub Issues", "Tickets both ways: severity from Bulwark, status from the issue."),
}
TEAM_CHANNELS = {
    "slack": ("Slack", "Incoming webhook."),
    "discord": ("Discord", "Channel webhook."),
    "teams": ("Microsoft Teams", "Incoming webhook."),
    "webhooks": ("Webhook", "Signed JSON to your own endpoint, SSRF-checked."),
}
PERSON_CHANNELS = {
    "in_app": ("Inbox", "In the app."),
    "email": ("Email", "Instant, or a daily digest."),
}


def _cats(values: Any) -> list[str]:
    return sorted(str(v) for v in values)


def scanners() -> list[dict[str, Any]]:
    from core.dast.adapters.nuclei import NUCLEI_IMAGE
    from core.dast.adapters.zap import ZAP_IMAGE
    from core.dast.campaign import TOOLS_FOR_MODE
    from core.scan import ADAPTERS, DEFAULT_TOOLS, HOSTED_DEFAULT_TOOLS

    out = []
    for name, adapter in ADAPTERS.items():
        spec = adapter.spec
        if name in DEFAULT_TOOLS:
            mode = "default"
        elif name in HOSTED_DEFAULT_TOOLS:
            mode = "hosted"
        else:
            mode = "opt-in"
        out.append(
            {
                "id": f"scanner:{name}",
                "name": name,
                "kind": "scanner",
                "categories": _cats(spec.categories),
                "languages": _cats(spec.languages),
                "version": spec.image.rsplit(":", 1)[-1],
                "mode": mode,
                "how": "Runs in a sandboxed container: no network, read-only, capabilities dropped.",
            }
        )
    images = {"zap-baseline": ZAP_IMAGE, "nuclei": NUCLEI_IMAGE}
    for tool in dict.fromkeys(t for tools in TOOLS_FOR_MODE.values() for t in tools):
        label, how = DAST_TOOLS[tool]
        out.append(
            {
                "id": f"scanner:{tool}",
                "name": label,
                "kind": "scanner",
                "categories": ["dast"],
                "languages": [],
                "version": images[tool].rsplit(":", 1)[-1],
                "mode": "passive" if tool in TOOLS_FOR_MODE["passive"] else "active",
                "how": how + " Egress only to the target, through Bulwark's proxy.",
            }
        )
    return out


def imports() -> list[dict[str, Any]]:
    from core.imports.parsers.registry import PARSERS
    from core.imports.parsers.universal import FORMATS

    out = []
    for p in PARSERS.values():
        out.append(
            {
                "id": f"import:{p.name}",
                "name": p.label or p.name,
                "kind": "import",
                "categories": _cats(p.categories),
                "formats": _cats(p.formats),
                "dedup": p.default_dedup,
                "ported_from_defectdojo": bool(p.ported_from),
                "how": "Upload a file; parsed in a sandbox with no network.",
            }
        )
    out.append(
        {
            "id": "import:universal",
            "name": "Any other report (universal mapper)",
            "kind": "import",
            "categories": [],
            "formats": sorted(FORMATS),
            "dedup": "fingerprint_v2",
            "ported_from_defectdojo": False,
            "how": "Map its fields once, preview, save; the saved mapping becomes a parser.",
        }
    )
    return out


def connectors() -> list[dict[str, Any]]:
    from core.connectors.service import KINDS

    return [
        {
            "id": f"connector:{k.name}",
            "name": k.label,
            "kind": "connector",
            "direction": k.direction,
            "credential": k.needs_credential,
            "permissions": k.permissions,
            "how": "Pulls on a schedule into a project." if k.direction == "pull"
            else "Pushes a project's findings out.",
        }
        for k in KINDS.values()
    ]  # fmt: skip


def workflow() -> list[dict[str, Any]]:
    from core.notify.kinds import PERSON_CHANNELS as PERSON
    from core.tickets.config import PROVIDERS

    out: list[dict[str, Any]] = []
    for p in PROVIDERS:
        label, how = TICKET_PROVIDERS[p]
        out.append({"id": f"tickets:{p}", "name": label, "kind": "tickets", "how": how})
    for c in PERSON:
        label, how = PERSON_CHANNELS[c]
        out.append({"id": f"notify:{c}", "name": label, "kind": "notifications", "how": how})
    for c, (label, how) in TEAM_CHANNELS.items():
        out.append({"id": f"notify:{c}", "name": label, "kind": "notifications", "how": how})
    return out


def agents() -> list[dict[str, Any]]:
    from core.fixagent.pr_command import MAX_FINDINGS
    from core.mcp_server.api import Identity
    from core.mcp_server.server import offered_tools

    everyone = Identity("catalogue", frozenset({"scans:read", "scans:write"}), "member")
    reading = offered_tools(everyone, allow_scans=False)
    extra = [t for t in offered_tools(everyone, allow_scans=True) if t not in reading]
    return [
        {"id": "agent:mcp", "name": "MCP server (bulwark mcp)", "kind": "agents",
         "how": f"Your own agent asks Bulwark as you: {', '.join(reading)}; "
                f"{', '.join(extra)} only with --allow-scans. Scanned text comes back labelled "
                "untrusted.",
         "permissions": "A personal API token; the shared token is refused"},
        {"id": "agent:github-fix", "name": "/fix on GitHub pull requests", "kind": "agents",
         "how": f"A member comments /fix: Bulwark previews up to {MAX_FINDINGS} new findings and "
                "the most it may spend; once confirmed, each verified patch is posted as a "
                "comment. Never for a fork.",
         "permissions": "The GitHub App: pull requests (read and write), the issue comment "
                        "event"},
    ]  # fmt: skip


def catalogue() -> dict[str, Any]:
    return {
        "_generated": "by scripts/gen-integrations.py from the code's own registries; do not edit",
        "categories": CATEGORY_LABELS,
        "items": [*scanners(), *imports(), *connectors(), *workflow(), *agents()],
    }


def render() -> str:
    return json.dumps(catalogue(), indent=1) + "\n"


def main() -> None:
    OUT.write_text(render())
    print(f"wrote {OUT} ({len(catalogue()['items'])} integrations)")


if __name__ == "__main__":
    main()
