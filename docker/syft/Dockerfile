# Syft generates the SBOM. Pinned by digest; same sandbox rules as every scanner (no network, read-only).
FROM anchore/syft:v1.52.0@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02
# Dev dependencies are included so the SBOM matches the scope Trivy and OSV-Scanner scan (see ADR-004 notes).
ENV HOME=/tmp \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true
USER 10001
ENTRYPOINT ["/syft"]
