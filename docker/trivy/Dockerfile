FROM aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
# Vulnerability DB is baked in at build time: the sandbox has no network at run time (ADR-002).
# Rebuild the image to refresh it (CI does this on a schedule; see docs/platform-support.md).
RUN trivy fs --cache-dir /db --download-db-only --no-progress /tmp \
 && chmod -R a+rwX /db
USER 10001
ENTRYPOINT ["trivy"]
