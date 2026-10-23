# One image for the API, the Celery worker and migrations.
FROM docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c AS dockercli

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
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
# Dependencies first, from the hash-pinned lock (scripts/lock-app-deps.sh): pip refuses any file whose
# hash differs and any dependency the lock does not pin, so a rebuild installs exactly what was
# reviewed. The lock carries the llm extra (optional Anthropic SDK, off unless enabled) and the otel
# extra (trace export). It is its own layer, so a code change does not reinstall them.
COPY docker/app/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY pyproject.toml README.md alembic.ini ./
COPY core core
COPY cli cli
COPY api api
COPY migrations migrations
# The project itself, against what is already installed: no index, no new packages, then every
# requirement checked as met.
RUN pip install --no-cache-dir --no-deps --no-build-isolation --no-index . && pip check
USER bulwark
