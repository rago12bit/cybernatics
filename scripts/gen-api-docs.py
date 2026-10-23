"""Generate docs/openapi.json and docs/api.md from the FastAPI app (design doc §11.2)."""

from __future__ import annotations

import json
from pathlib import Path

from api.deps import AppState
from api.main import create_app
from core.config import Settings

ROOT = Path(__file__).resolve().parent.parent


class _NoSub:
    def subscribe(self, scan_id: str):  # type: ignore[no-untyped-def]
        raise NotImplementedError


def severity_doc() -> str:
    from core.scoring.severity import as_markdown

    return (
        "# Severity normalization matrix\n\n"
        "_Generated from `core/scoring/severity.py` by `scripts/gen-api-docs.py`; do not edit._\n\n"
        "Tool severity vocabularies are not comparable. This table is a **judgment call**, not a "
        "derived truth: it maps each tool's native label to one shared scale.\n\n"
        + as_markdown()
        + "\n"
    )


def openapi_spec() -> dict:
    """The live FastAPI app's own OpenAPI document -- the single source of truth `api.md` and
    `openapi.json` are both generated from, so the two can never disagree with each other, only
    (if this script hasn't been re-run) with the app itself."""
    base = Settings.from_env()
    settings = Settings(**{**base.__dict__, "api_token": "x" * 32})
    app = create_app(AppState(settings, lambda: None, lambda _sid, _org: None, _NoSub()))  # type: ignore[arg-type,return-value]
    return app.openapi()


def api_doc(spec: dict) -> str:
    lines = [
        f"# {spec['info']['title']} reference",
        "",
        f"_Generated from the OpenAPI {spec['openapi']} spec by "
        "`scripts/gen-api-docs.py`; do not edit._",
        "",
        "All endpoints except `/healthz` need `Authorization: Bearer <BULWARK_API_TOKEN>`.",
        'The WebSocket `/scans/{id}/ws` authenticates with a first message `{"token": "..."}` (or `{}` '
        "from a",
        "signed-in browser, see below) and then streams `snapshot`, `tool.finished` and "
        "`scan.finished` events.",
        "",
    ]
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            lines += [f"## `{method.upper()} {path}`", "", op.get("summary", ""), ""]
            for p in op.get("parameters", []):
                lines.append(
                    f"- `{p['name']}` ({p['in']}{', required' if p.get('required') else ''})"
                )
            lines.append("")
    lines += [
        "## Live progress (WebSocket)",
        "",
        "`GET /scans/{scan_id}/ws` (not part of OpenAPI).",
        "",
        "The first message authenticates, by the same rules as every other route:",
        "",
        '- `{"token": "<token>"}`: the shared `BULWARK_API_TOKEN`, a scoped token, or a person\'s '
        "own token. Only",
        '  the shared token may add `"org": "<organization id>"` to choose an organization; any '
        "other token",
        "  always sees its own.",
        "- `{}`: a browser signed in with a session cookie. The cookie counts only when the "
        "handshake's `Origin`",
        "  is in `BULWARK_CORS_ORIGINS`, so another site's page cannot open the socket as the "
        "signed-in person.",
        "",
        "The caller needs `scans:read` on the scan's project. Closes with `4401` when nothing "
        "authenticates, and",
        "with `4404` when the scan does not exist or the caller may not read it (the two look "
        "the same).",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    spec = openapi_spec()
    (ROOT / "docs" / "openapi.json").write_text(json.dumps(spec, indent=2) + "\n")
    (ROOT / "docs" / "api.md").write_text(api_doc(spec))
    (ROOT / "docs" / "severity-matrix.md").write_text(severity_doc())


if __name__ == "__main__":
    main()
