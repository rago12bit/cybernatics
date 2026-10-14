FROM aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa
# Vulnerability DB is baked in at build time: the sandbox has no network at run time (ADR-002).
# Rebuild the image to refresh it (CI does this on a schedule; see docs/platform-support.md).
RUN trivy fs --cache-dir /db --download-db-only --no-progress /tmp \
 && chmod -R a+rwX /db
USER 10001
ENTRYPOINT ["trivy"]
