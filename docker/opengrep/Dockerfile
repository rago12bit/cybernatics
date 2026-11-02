# Opengrep (LGPL-2.1): a community-maintained fork of the Semgrep engine, used instead of Semgrep
# for HOSTED scans (ADR-0038) -- Semgrep's own community/Pro rules (docker/semgrep/) are licensed
# for internal business use only (ADR-006), which a hosted, multi-tenant deployment is not.
#
# No official Docker image exists upstream (opengrep ships platform binaries via GitHub Releases,
# signed, not a container) -- https://github.com/opengrep/opengrep/releases. Pinned by sha256, one
# binary per architecture; `docker buildx` sets TARGETARCH automatically for either. The build also
# checks each binary's cosign signature against opengrep's release workflow (THREAT-MODEL T10).
#
# Deliberately does NOT bundle github.com/opengrep/opengrep-rules: that ruleset carries a
# "Commons Clause" condition on top of its own LGPL-2.1 ("the License does not grant ... the right
# to Sell the Software", where "Sell" is defined to include offering it as a hosted service) --
# the exact same restriction this image exists to get away from. Rules live in
# docker/opengrep/rules/, authored for this project (see docker/opengrep/rules/LICENSE).
FROM ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d AS cosign

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
ARG OPENGREP_VERSION=1.30.0
# Who signs opengrep's release binaries (the certificate on each one's .sig), THREAT-MODEL T10.
ARG SIGNER=https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/main
ARG TARGETARCH

# sha256 of opengrep_musllinux_{x86,aarch64} for v1.30.0 (github.com/opengrep/opengrep/releases) --
# verified by downloading both and hashing them, not copied from a third party's claim.
ARG SHA256_AMD64=ee21fa70714531e1eccbcb50993a871e198fb0f4ade254ef7636c433304fe4bd
ARG SHA256_ARM64=937d0f35fc05af8877f5f34e04465f2466a8da3c33c2a0d510b8a896383354ef

# cosign is mounted for this step only, so it is not left in a layer of the scanner image.
RUN --mount=type=bind,from=cosign,source=/ko-app/cosign,target=/tmp/cosign \
    apk add --no-cache curl && \
    if [ "$TARGETARCH" = "arm64" ]; then \
      URL="https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_musllinux_aarch64"; \
      SHA256="$SHA256_ARM64"; \
    else \
      URL="https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_musllinux_x86"; \
      SHA256="$SHA256_AMD64"; \
    fi && \
    curl -fsSL -o /usr/local/bin/opengrep "$URL" && \
    curl -fsSL -o /tmp/opengrep.sig "$URL.sig" && curl -fsSL -o /tmp/opengrep.cert "$URL.cert" && \
    /tmp/cosign verify-blob --certificate /tmp/opengrep.cert --signature /tmp/opengrep.sig \
      --certificate-identity "$SIGNER" --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      /usr/local/bin/opengrep && \
    echo "$SHA256  /usr/local/bin/opengrep" | sha256sum -c - && \
    chmod +x /usr/local/bin/opengrep && \
    rm /tmp/opengrep.sig /tmp/opengrep.cert && \
    apk del curl

COPY rules /rules
RUN adduser -D -u 10001 scanner && mkdir -p /scratch && chown scanner:scanner /scratch
USER 10001
# Sandbox has a read-only rootfs and no network: never phone home (same posture as docker/semgrep's
# own image). Unlike every other adapter, HOME/TMPDIR point at /scratch (core.adapters.opengrep's
# own `writable_volumes=("/scratch",)`), not /tmp: opengrep's binary self-extracts a child
# executable and execs it from there, and the sandbox's shared /tmp is a `noexec` tmpfs every
# adapter gets -- confirmed live that self-extraction fails against it ("couldn't launch child
# (exec): Permission denied") and succeeds against a plain writable volume instead.
ENV HOME=/scratch TMPDIR=/scratch
ENTRYPOINT ["/usr/local/bin/opengrep"]
