# Bulwark

Unified security scanning platform. Bulwark orchestrates best-in-class open-source scanners in
sandboxed containers, normalizes their output to one schema, deduplicates overlapping findings, and
ranks by realistic exploitability (EPSS, CISA KEV, reachability) rather than raw severity.

> Status: pre-alpha (Week 1 scaffold). Design: see the project design document.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check . && black --check . && mypy && pytest
```

License: Apache-2.0
