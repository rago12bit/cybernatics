# Syft generates the SBOM. Same sandbox rules as every scanner (no network, read-only).
#
# Built from Anchore's release, not their image (THREAT-MODEL T10): the image is unsigned, but the
# release's checksum file is signed with cosign by Anchore's release workflow. The build checks that
# signature against that exact workflow, then the archive against the checksum, and fails otherwise.
FROM ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d AS cosign

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS verify
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

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
COPY --from=verify /syft /syft
# Dev dependencies are included so the SBOM matches the scope Trivy and OSV-Scanner scan (see ADR-004 notes).
ENV HOME=/tmp \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true
USER 10001
ENTRYPOINT ["/syft"]
