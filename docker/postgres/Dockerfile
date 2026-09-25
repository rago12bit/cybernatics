# PostgreSQL 16 + pgvector, on the same Alpine base as before so existing data volumes stay compatible.
# pgvector is pinned to a release tag and compiled from source (no extra service, ADR-009).
FROM postgres:16-alpine AS build
ARG PGVECTOR_VERSION=v0.8.0
RUN apk add --no-cache --virtual .build-deps build-base git \
 && git clone --branch ${PGVECTOR_VERSION} --depth 1 https://github.com/pgvector/pgvector.git /tmp/pgvector \
 && make -C /tmp/pgvector OPTFLAGS="" with_llvm=no \
 && make -C /tmp/pgvector install with_llvm=no \
 && apk del .build-deps && rm -rf /tmp/pgvector
