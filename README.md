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

## Building the scanner images

Scanner images run sandboxed (no network). Build the local ones once:

```bash
docker build -t bulwark/bandit:1.7.10 docker/bandit
docker/semgrep/fetch-rules.sh && docker build -t bulwark/semgrep:1.90.0 docker/semgrep
```

Gitleaks uses the upstream image. Semgrep's rules are fetched at build time and are for your own
internal use only — see [ADR-006](docs/adr/0006-semgrep-rules-licensing.md).
