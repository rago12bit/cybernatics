# One image for the API, the Celery worker and migrations.
FROM docker:27-cli AS dockercli

FROM python:3.12-slim
# xmlsec1: SAML signature checks (Week 75, core.identity.saml, via pysaml2).
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates xmlsec1 \
 && rm -rf /var/lib/apt/lists/*
# Docker CLI only: it talks to the restricted socket proxy over TCP, never the raw socket.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
# OPA, pinned and checked: rule conditions (plan §45) and policy gates (§20.4) are Rego. The same
# release and checksums CI uses; the build fails on any mismatch.
ARG TARGETARCH
ARG OPA_VERSION=1.21.0
RUN python -c "import hashlib, sys, urllib.request; \
sums = {'amd64': '5eef70644868bb04d0556bcc795ee42f2ab379e73f51d1bfa30f83e1305bc9b9', \
        'arm64': '0ec34027c15b4d969c21d01ed570fe14fbebd508a08157043ab09f9a0dccbee6'}; \
arch = '${TARGETARCH:-amd64}'; \
url = 'https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_' + arch + '_static'; \
data = urllib.request.urlopen(url, timeout=120).read(); \
digest = hashlib.sha256(data).hexdigest(); \
open('/usr/local/bin/opa', 'wb').write(data) if digest == sums[arch] \
  else sys.exit('opa checksum mismatch: ' + digest)" \
 && chmod 0755 /usr/local/bin/opa && opa version
RUN useradd -m -u 10002 bulwark
WORKDIR /app
COPY pyproject.toml README.md alembic.ini ./
COPY core core
COPY cli cli
COPY api api
COPY migrations migrations
RUN pip install --no-cache-dir '.[llm,otel]'  # llm: optional Anthropic SDK (off unless enabled); otel: trace export
USER bulwark
