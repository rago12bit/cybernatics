# Syft generates the SBOM. Same sandbox rules as every scanner (no network, read-only).
#
# Built from Anchore's release, not their image (THREAT-MODEL T10): the image is unsigned, but the
# release's checksum file is signed with cosign by Anchore's release workflow. The build checks that
# signature against that exact workflow, then the archive against the checksum, and fails otherwise.
FROM ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8 AS cosign

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS verify
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
ARG SYFT_VERSION=1.52.0
ARG TARGETARCH
ARG SIGNER=https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main
WORKDIR /rel
RUN apk add --no-cache curl \
 && base="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}" \
 && sums="syft_${SYFT_VERSION}_checksums.txt" \
 && tarball="syft_${SYFT_VERSION}_linux_${TARGETARCH:-amd64}.tar.gz" \
 && for f in "$sums" "$sums.sig" "$sums.pem" "$tarball"; do curl -fsSLO "$base/$f"; done \
 && cosign verify-blob --certificate "$sums.pem" --signature "$sums.sig" \
      --certificate-identity "$SIGNER" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$sums" \
 && grep "  $tarball\$" "$sums" | sha256sum -c - \
 && tar -xzf "$tarball" syft && install -m 0755 syft /syft

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=verify /syft /syft
# Dev dependencies are included so the SBOM matches the scope Trivy and OSV-Scanner scan (see ADR-004 notes).
ENV HOME=/tmp \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true
USER 10001
ENTRYPOINT ["/syft"]
