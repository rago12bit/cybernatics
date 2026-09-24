# One image for the API, the Celery worker and migrations.
FROM docker:27-cli AS dockercli

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# Docker CLI only: it talks to the restricted socket proxy over TCP, never the raw socket.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
RUN useradd -m -u 10002 bulwark
WORKDIR /app
COPY pyproject.toml README.md alembic.ini ./
COPY core core
COPY cli cli
COPY api api
COPY migrations migrations
RUN pip install --no-cache-dir .
USER bulwark
