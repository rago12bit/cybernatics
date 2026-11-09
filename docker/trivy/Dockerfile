FROM aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
# Vulnerability DB is baked in at build time: the sandbox has no network at run time (ADR-002).
# Rebuild the image to refresh it (CI does this on a schedule; see docs/platform-support.md).
RUN trivy fs --cache-dir /db --download-db-only --no-progress /tmp \
 && chmod -R a+rwX /db
USER 10001
ENTRYPOINT ["trivy"]
