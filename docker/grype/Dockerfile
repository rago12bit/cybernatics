# Grype: SCA. The vulnerability database is baked in at build time (the sandbox has no network at run time).
# Rebuild the image to refresh it, as with Trivy.
#
# Built from Anchore's release, not their image (THREAT-MODEL T10): the image is unsigned, but the
# release's checksum file is signed with cosign by Anchore's release workflow. The build checks that
# signature against that exact workflow, then the archive against the checksum, and fails otherwise.
FROM ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8 AS cosign

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS verify
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
ARG GRYPE_VERSION=0.119.0
ARG TARGETARCH
ARG SIGNER=https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main
WORKDIR /rel
RUN apk add --no-cache curl \
 && base="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}" \
 && sums="grype_${GRYPE_VERSION}_checksums.txt" \
 && tarball="grype_${GRYPE_VERSION}_linux_${TARGETARCH:-amd64}.tar.gz" \
 && for f in "$sums" "$sums.sig" "$sums.pem" "$tarball"; do curl -fsSLO "$base/$f"; done \
 && cosign verify-blob --certificate "$sums.pem" --signature "$sums.sig" \
      --certificate-identity "$SIGNER" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$sums" \
 && grep "  $tarball\$" "$sums" | sha256sum -c - \
 && tar -xzf "$tarball" grype && install -m 0755 grype /grype

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
COPY --from=verify /grype /usr/local/bin/grype
RUN adduser -D -u 10001 scanner && mkdir /db && chown scanner /db
USER 10001
ENV HOME=/tmp GRYPE_DB_CACHE_DIR=/db GRYPE_DB_AUTO_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false
RUN grype db update
ENTRYPOINT ["grype"]
