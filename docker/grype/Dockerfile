# Grype: SCA. The vulnerability database is baked in at build time (the sandbox has no network at run time).
# Rebuild the image to refresh it, as with Trivy.
FROM anchore/grype:v0.120.1@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe AS grype

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=grype /grype /usr/local/bin/grype
RUN adduser -D -u 10001 scanner && mkdir /db && chown scanner /db
USER 10001
ENV HOME=/tmp GRYPE_DB_CACHE_DIR=/db GRYPE_DB_AUTO_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false
RUN grype db update
ENTRYPOINT ["grype"]
