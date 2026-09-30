#!/usr/bin/env bash
# Generate a local CA and per-service client certificates for Postgres mTLS (Week 47 task 3, plan
# §22.2, ADR-0033). Dev/self-signed only -- a real deployment needs its own CA and a real issuance
# process (cert-manager or equivalent), not this script; see docs/data-protection.md.
set -euo pipefail
cd "$(dirname "$0")/.."
# An explicit output dir (tests/integration/test_postgres_mtls_docker.py passes a temp one) skips
# the "already exists" guard below -- a fresh directory never has a stale CA to protect.
OUT="${1:-certs}"
if [[ -z "${1:-}" && -f "$OUT/ca.crt" ]]; then echo "$OUT/ already has a CA; leaving it alone."; exit 0; fi
mkdir -p "$OUT"

# CA
openssl genrsa -out "$OUT/ca.key" 4096 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$OUT/ca.key" -sha256 -days 3650 \
  -out "$OUT/ca.crt" -subj "/CN=bulwark-internal-ca" >/dev/null 2>&1

# Server cert for the postgres container -- SAN must match how clients actually connect to it
# (the compose service name "postgres"), since sslmode=verify-full checks this, not just the CA chain.
openssl genrsa -out "$OUT/server.key" 2048 >/dev/null 2>&1
openssl req -new -key "$OUT/server.key" -out "$OUT/server.csr" -subj "/CN=postgres" >/dev/null 2>&1
cat > "$OUT/server.ext" <<'EOF'
subjectAltName=DNS:postgres,DNS:localhost
EOF
openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/server.crt" -days 825 -sha256 -extfile "$OUT/server.ext" >/dev/null 2>&1
rm -f "$OUT/server.csr" "$OUT/server.ext"

# One client cert per service (Week 47 task 3), including the table-owning `bulwark` role the
# `migrate` service connects as: the certificate's CN is what Postgres's clientcert=verify-full
# (docker/postgres/pg_hba.conf) matches against the connecting role name -- see migration 0020 for
# the matching bulwark_api/bulwark_worker/bulwark_fixagent LOGIN roles. `bulwark` itself is the
# most privileged role of the four, so it gets mTLS too, not an exemption.
for role in bulwark bulwark_api bulwark_worker bulwark_fixagent; do
  openssl genrsa -out "$OUT/client_${role}.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$OUT/client_${role}.key" -out "$OUT/client_${role}.csr" \
    -subj "/CN=${role}" >/dev/null 2>&1
  openssl x509 -req -in "$OUT/client_${role}.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
    -CAcreateserial -out "$OUT/client_${role}.crt" -days 825 -sha256 >/dev/null 2>&1
  rm -f "$OUT/client_${role}.csr"
done

chmod 600 "$OUT"/*.key
chmod 644 "$OUT"/ca.crt "$OUT"/server.crt "$OUT"/client_*.crt
echo "Wrote $OUT/ (CA + server cert + one client cert per service). Never commit this directory."
