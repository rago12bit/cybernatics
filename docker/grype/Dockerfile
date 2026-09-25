# Grype: SCA. The vulnerability database is baked in at build time (the sandbox has no network at run time).
# Rebuild the image to refresh it, as with Trivy.
FROM anchore/grype:v0.119.0 AS grype

FROM alpine:3.20
COPY --from=grype /grype /usr/local/bin/grype
RUN adduser -D -u 10001 scanner && mkdir /db && chown scanner /db
USER 10001
ENV HOME=/tmp GRYPE_DB_CACHE_DIR=/db GRYPE_DB_AUTO_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false
RUN grype db update
ENTRYPOINT ["grype"]
