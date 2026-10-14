FROM aquasec/trivy:0.55.2@sha256:addfb8fd6b9e520c25b22c61d8aa5d58ecd7879177aa959f952bf4734f4e3f60
# Vulnerability DB is baked in at build time: the sandbox has no network at run time (ADR-002).
# Rebuild the image to refresh it (CI does this on a schedule; see docs/platform-support.md).
RUN trivy fs --cache-dir /db --download-db-only --no-progress /tmp \
 && chmod -R a+rwX /db
USER 10001
ENTRYPOINT ["trivy"]
