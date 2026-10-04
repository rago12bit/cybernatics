# Parses one uploaded report inside the scanner sandbox (plan §42.2). Build from the REPOSITORY ROOT:
#   docker build -f docker/ingest-parser/Dockerfile -t bulwark/ingest-parser:1 .
#
# Only the modules the parsers import are copied -- not the API, the database layer or any
# credentials -- so a bug triggered by a hostile report has nothing to reach. tests/integration/
# test_ingest_sandbox_docker.py builds this image and runs a real file through it, which fails if a
# parser starts importing something that is not copied here.
FROM python:3.12-slim
RUN pip install --no-cache-dir ijson==3.5.1 google-re2==1.1.20251105 defusedxml==0.7.1 \
    && useradd -m -u 10001 parser
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY core/__init__.py /app/core/__init__.py
COPY core/models /app/core/models
COPY core/scoring /app/core/scoring
COPY core/sarif.py /app/core/sarif.py
COPY core/dast/__init__.py core/dast/mapping.py /app/core/dast/
COPY core/adapters/__init__.py core/adapters/base.py core/adapters/osv_scanner.py core/adapters/helpers.py core/adapters/grype.py core/adapters/trivy.py /app/core/adapters/
COPY core/imports/__init__.py /app/core/imports/__init__.py
COPY core/imports/parsers /app/core/imports/parsers
USER 10001
ENTRYPOINT ["python", "-m", "core.imports.parsers.worker"]
