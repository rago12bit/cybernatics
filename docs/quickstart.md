# Quickstart

## The full stack (web UI + API + worker)

Needs Docker, with Compose. The first build downloads scanner databases (about 1.4 GB for Trivy).

```bash
./scripts/init-env.sh                       # writes .env with random secrets
docker compose --profile scanners build     # app image + the custom scanner images
docker compose up -d
```

Open **http://localhost:3000**. The first page is a real sample report, no sign-in needed. To scan
your own code, go to **/app**, paste the API token from `.env` (`BULWARK_API_TOKEN`) and submit a
Git URL or archive.

### Or drive it from the command line / CI

The API never scans server-side paths -- only Git URLs and uploaded archives:

```bash
TOKEN=$(grep ^BULWARK_API_TOKEN .env | cut -d= -f2)
curl -X POST localhost:8000/scans -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"source": {"type": "git", "url": "https://github.com/OWASP/NodeGoat"}}'
curl -X POST localhost:8000/scans/upload -H "Authorization: Bearer $TOKEN" -F archive=@project.zip
curl localhost:8000/scans/<id>                                    -H "Authorization: Bearer $TOKEN"
curl "localhost:8000/scans/<id>/findings?severity=HIGH&limit=20"  -H "Authorization: Bearer $TOKEN"
```

Live progress: connect a WebSocket to `/scans/<id>/ws`, send `{"token": "<token>"}`, and receive
`snapshot`, `tool.finished` and `scan.finished` events. Every endpoint is in the
[API reference](api.md).

## Just the CLI, no server at all

```bash
pip install -e ".[dev]"
bulwark scan https://github.com/OWASP/NodeGoat
```

`bulwark scan` also takes a local directory or a `.zip`/`.tar.gz` archive, and `--format sarif`,
`--format html` or `--format pdf` instead of the default JSON. Scan only what changed in a pull
request and compare it against the base branch's own baseline with `bulwark ci compare` -- see the
[GitHub Action](github-action.md) for the wired-up version of that workflow.

## Block a bad commit before it happens

Rather than catching a leaked credential in CI, catch it before it's committed. This needs no
Docker and no server -- a native, no-Docker complement to the tools above, fast enough to run on
every commit:

```bash
bulwark precommit install          # writes .git/hooks/pre-commit in the current repo
```

Or, if your repository already uses the [`pre-commit`](https://pre-commit.com) framework, add this
project's `.pre-commit-hooks.yaml` entry to your `.pre-commit-config.yaml` instead -- see
[`bulwark precommit --help`](https://github.com/Rag2102/cyberimp/blob/main/.pre-commit-hooks.yaml)
for both.

## Next

- [Concepts](concepts/architecture.md) -- how a scan actually works.
- [Writing a plugin](plugins.md) -- add a scanner Bulwark doesn't ship.
- [Policy cookbook](policy.md) -- rules a severity threshold alone can't express.
