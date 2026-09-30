#!/bin/sh
# Stages the mTLS CA/server certificate into the data directory with the ownership and permissions
# Postgres requires (0600, owned by the postgres user) before starting it -- a bind-mounted cert
# directory is typically owned by the host user, which Postgres refuses to use for its private key
# (Week 47 task 3, plan §22.2, ADR-0033). Verified live: without this staging step Postgres exits at
# startup with "private key file has group or world access."
set -e
mkdir -p /var/lib/postgresql/certs
cp /certs-in/ca.crt /certs-in/server.crt /certs-in/server.key /var/lib/postgresql/certs/
chown postgres:postgres /var/lib/postgresql/certs/*
chmod 600 /var/lib/postgresql/certs/server.key
chmod 644 /var/lib/postgresql/certs/ca.crt /var/lib/postgresql/certs/server.crt
exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file=/var/lib/postgresql/certs/server.crt \
  -c ssl_key_file=/var/lib/postgresql/certs/server.key \
  -c ssl_ca_file=/var/lib/postgresql/certs/ca.crt \
  -c hba_file=/etc/postgresql-custom/pg_hba.conf
