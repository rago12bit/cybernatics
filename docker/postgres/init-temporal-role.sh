#!/bin/sh
# Runs once, only on first-ever initialization of an empty data directory (the standard Postgres
# image's own docker-entrypoint-initdb.d convention) -- creates the dedicated role Temporal's
# third-party auto-setup image connects as (Week 47 task 3, plan §22.2, ADR-0033), so it never
# shares an identity with any of Bulwark's own mTLS-authenticated services. CREATEDB is required:
# Temporal's auto-setup creates its own `temporal`/`temporal_visibility` databases on first run.
set -e
: "${TEMPORAL_DB_PASSWORD:?TEMPORAL_DB_PASSWORD must be set for the postgres container (see scripts/init-env.sh)}"
# The password is interpolated directly, not bound as a parameter (psql -c has no parameter binding
# for DDL literals) -- safe only because it always comes from scripts/init-env.sh's own random hex
# generation (openssl rand -hex 24), which can never contain a quote or shell metacharacter.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -c "CREATE ROLE temporal_svc LOGIN CREATEDB PASSWORD '$TEMPORAL_DB_PASSWORD';"
