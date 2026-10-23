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
# Encrypts the integration secrets (webhook URLs, GitHub/Jira tokens) in the database. Keep a copy:
# without it they cannot be read back and have to be entered again (docs/data-protection.md).
BULWARK_SECRETS_KEY=$(openssl rand -hex 32)
# OpenBao's dev-mode root token (Week 47, plan §22.2): fine for local dev, where OpenBao auto-unseals
# and this token is already root -- production must never run OpenBao in dev mode or use a token
# generated this way (see docs/data-protection.md).
BULWARK_OPENBAO_TOKEN=$(rand)
# Temporal's own auto-setup image (Week 47 task 3, plan §22.2): a dedicated, password-authenticated
# role, never a member of bulwark_app -- see docker/postgres/init-temporal-role.sh.
TEMPORAL_DB_PASSWORD=$(rand)
# Must be a path shared with the Docker host (scanner containers bind-mount from it).
BULWARK_WORKDIR=$WORKDIR
EOF
chmod 600 .env
echo "Wrote .env (API token: see BULWARK_API_TOKEN inside it)."
echo "Next: ./scripts/gen-mtls-certs.sh && docker compose --profile scanners build"
