# Syft generates the SBOM. Pinned by digest; same sandbox rules as every scanner (no network, read-only).
FROM anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa
# Dev dependencies are included so the SBOM matches the scope Trivy and OSV-Scanner scan (see ADR-004 notes).
ENV HOME=/tmp \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true
USER 10001
ENTRYPOINT ["/syft"]
