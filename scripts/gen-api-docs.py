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


def main() -> None:
    base = Settings.from_env()
    settings = Settings(**{**base.__dict__, "api_token": "x" * 32})
    app = create_app(AppState(settings, lambda: None, lambda _: None, _NoSub()))  # type: ignore[arg-type,return-value]
    spec = app.openapi()
    (ROOT / "docs" / "openapi.json").write_text(json.dumps(spec, indent=2) + "\n")
    lines = [
        f"# {spec['info']['title']} reference",
        "",
        f"_Generated from the OpenAPI {spec['openapi']} spec by "
        "`scripts/gen-api-docs.py`; do not edit._",
        "",
        "All endpoints except `/healthz` need `Authorization: Bearer <BULWARK_API_TOKEN>`.",
        'The WebSocket `/scans/{id}/ws` authenticates with a first message `{"token": "..."}`',
        "and then streams `snapshot`, `tool.finished` and `scan.finished` events.",
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
    ]
    (ROOT / "docs" / "api.md").write_text("\n".join(lines))


if __name__ == "__main__":
    main()
