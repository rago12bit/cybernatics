# PostgreSQL 16 + pgvector, on the same Alpine base as before so existing data volumes stay compatible.
# pgvector is pinned to a release tag and compiled from source (no extra service, ADR-009).
FROM postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea AS build
ARG PGVECTOR_VERSION=v0.8.0
RUN apk add --no-cache --virtual .build-deps build-base git \
 && git clone --branch ${PGVECTOR_VERSION} --depth 1 https://github.com/pgvector/pgvector.git /tmp/pgvector \
 && make -C /tmp/pgvector OPTFLAGS="" with_llvm=no \
 && make -C /tmp/pgvector install with_llvm=no \
 && apk del .build-deps && rm -rf /tmp/pgvector

# mTLS for every network connection (Week 47 task 3, plan §22.2, ADR-0033) -- pg_hba.conf is baked
# into the image (it's not a secret), the CA/server certificate themselves are mounted at runtime
# from scripts/gen-mtls-certs.sh's output, never baked in.
COPY pg_hba.conf /etc/postgresql-custom/pg_hba.conf
COPY docker-entrypoint-wrapper.sh /usr/local/bin/docker-entrypoint-wrapper.sh
COPY init-temporal-role.sh /docker-entrypoint-initdb.d/init-temporal-role.sh
RUN chmod +x /usr/local/bin/docker-entrypoint-wrapper.sh /docker-entrypoint-initdb.d/init-temporal-role.sh
ENTRYPOINT ["docker-entrypoint-wrapper.sh"]
CMD ["postgres"]
