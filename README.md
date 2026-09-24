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
docker build -t bulwark/trivy:0.55.2 docker/trivy          # bakes in a ~1.4 GB vuln DB
docker build -t bulwark/osv-scanner:1.9.2 docker/osv-scanner  # offline DBs: PyPI, npm, Go
```

Vulnerability databases are baked in at build time (the sandbox has no network at run time), so
rebuild the Trivy and OSV images to refresh them.

## Usage

```bash
bulwark scan ./my-project                                # directory
bulwark scan project.zip                                 # archive (zip / tar.gz), extracted safely
bulwark scan https://github.com/owner/repo               # public Git URL (github/gitlab/bitbucket)
bulwark scan ./my-project --tools bandit,trivy           # subset of tools
```

Tools run in parallel; a tool that fails or times out is reported in `tool_status` and never fails
the scan. To fan tools out to Celery workers instead of local threads:

```bash
docker run -d -p 6379:6379 redis:7-alpine
celery -A core.tasks worker -P threads -c 5     # threads: work is subprocess-bound
bulwark scan ./my-project --distributed
```

Gitleaks uses the upstream image. Semgrep's rules are fetched at build time and are for your own
internal use only — see [ADR-006](docs/adr/0006-semgrep-rules-licensing.md).
