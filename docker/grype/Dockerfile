# Grype: SCA. The vulnerability database is baked in at build time (the sandbox has no network at run time).
# Rebuild the image to refresh it, as with Trivy.
FROM anchore/grype:v0.119.0@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3 AS grype

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
COPY --from=grype /grype /usr/local/bin/grype
RUN adduser -D -u 10001 scanner && mkdir /db && chown scanner /db
USER 10001
ENV HOME=/tmp GRYPE_DB_CACHE_DIR=/db GRYPE_DB_AUTO_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false
RUN grype db update
ENTRYPOINT ["grype"]
