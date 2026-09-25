# Contributing to Bulwark

Bug reports, adapter improvements and documentation fixes are welcome. For anything larger than a small
fix, open an issue first so we can agree on the approach.

## Setup

Needs Python 3.10+, Node 20+ and Docker.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cd web && npm ci
```

## Checks (CI runs exactly these)

```bash
ruff check . && black --check . && mypy && pytest          # backend; 80% coverage is enforced
cd web && npm run typecheck && npm test && npm run build   # frontend
```

`pytest` runs the fast unit tests. `tests/integration` runs the real scanner containers; build the images
first (see the README) or skip that folder.

## Where things live

| Path | What |
|---|---|
| `core/adapters/` | One adapter per scanner: builds the command, parses output into `Finding`s |
| `core/correlation/` | Cross-tool merging ([ADR-004](docs/adr/0004-fingerprinting-and-correlation.md)) |
| `core/taxonomy/` | CWE and OWASP mapping ([docs/taxonomy.md](docs/taxonomy.md)) |
| `core/pipeline.py`, `core/scan.py` | The API path and the CLI path. Changes to the finding flow usually need both |
| `api/`, `core/persistence/`, `migrations/` | FastAPI service, SQLAlchemy models, Alembic |
| `web/` | Next.js UI |
| `docs/adr/` | Design decisions; add one when you change a decision |

## Adding or changing a scanner adapter

1. Run the real tool on a frozen fixture in `tests/fixtures/` and save its raw output under
   `tests/golden/<tool>/`. Tests parse real output, not hand-written JSON.
2. Fixtures are excluded from black and ruff on purpose (reformatting shifts line numbers); do not
   reformat them.
3. The adapter must never put a secret into a finding. Add a test with a planted secret.
4. Run the tool inside its container with the sandbox flags; never relax them to make a scan work.

## Rules that are easy to break

- **Correlate before redacting.** Redaction placeholders look identical and would merge distinct findings.
- **Scanner output and repo contents are untrusted.** Validate, and in the UI render as text. Never build a
  link from an unvalidated string (`web/lib/safe.ts`).
- **The web UI has a strict CSP:** no inline `style` attributes, no inline scripts. Use CSS classes.
- **A change needs a test that fails without it.** Please show that in the pull request.

## Commits and pull requests

Commits follow [Conventional Commits](https://www.conventionalcommits.org) (`feat:`, `fix:`, `docs:`, ...);
CI lints them. Keep pull requests focused, describe what you verified and what you did not, and update
`CHANGELOG.md` under *Unreleased*.

By contributing you agree your work is licensed under Apache-2.0, the project licence.
