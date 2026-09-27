#!/usr/bin/env bash
# Generate a local .env with random secrets and create the shared scan work directory.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then echo ".env already exists; leaving it alone."; exit 0; fi
rand() { openssl rand -hex 24; }
WORKDIR="${BULWARK_WORKDIR:-/tmp/bulwark}"
mkdir -p "$WORKDIR" && chmod 1777 "$WORKDIR"
cat > .env <<EOF
POSTGRES_PASSWORD=$(rand)
# Credentials for the non-superuser role the API/worker connect as (ADR-0013); migrations still run
# as POSTGRES_PASSWORD's role so they can create it and alter schema. Required for Postgres
# Row-Level Security to do anything at all -- a superuser bypasses RLS regardless of policies.
APP_DB_PASSWORD=$(rand)
S3_ACCESS_KEY=bulwark
S3_SECRET_KEY=$(rand)
BULWARK_API_TOKEN=$(rand)
# Must be a path shared with the Docker host (scanner containers bind-mount from it).
BULWARK_WORKDIR=$WORKDIR
EOF
chmod 600 .env
echo "Wrote .env (API token: see BULWARK_API_TOKEN inside it). Next: docker compose --profile scanners build"
