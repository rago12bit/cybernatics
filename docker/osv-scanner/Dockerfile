# OSV-Scanner, built from Google's release, not their image (THREAT-MODEL T10): the image is
# unsigned, but each release binary has SLSA build provenance signed through Sigstore by the
# google/osv-scanner build. slsa-verifier checks the binary against it -- built from that repository,
# at this release's tag -- and the build fails otherwise. slsa-verifier itself is pinned by sha256
# (downloaded and hashed on 2026-10-15; its own provenance can only be checked by itself).
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS verify
ARG OSV_VERSION=2.6.0
ARG SLSA_VERIFIER_VERSION=2.7.1
ARG SLSA_VERIFIER_SHA256_AMD64=946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339
ARG SLSA_VERIFIER_SHA256_ARM64=5d3b2349ede7bfec19e7a21569f18b9f7410145ad12e9584b175370669e14061
ARG TARGETARCH
WORKDIR /rel
RUN apk add --no-cache curl \
 && arch="${TARGETARCH:-amd64}" \
 && if [ "$arch" = arm64 ]; then sv_sum="$SLSA_VERIFIER_SHA256_ARM64"; else sv_sum="$SLSA_VERIFIER_SHA256_AMD64"; fi \
 && curl -fsSL -o slsa-verifier "https://github.com/slsa-framework/slsa-verifier/releases/download/v${SLSA_VERIFIER_VERSION}/slsa-verifier-linux-$arch" \
 && echo "$sv_sum  slsa-verifier" | sha256sum -c - && chmod +x slsa-verifier \
 && base="https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}" \
 && curl -fsSL -o "osv-scanner_linux_$arch" "$base/osv-scanner_linux_$arch" \
 && curl -fsSL -o multiple.intoto.jsonl "$base/multiple.intoto.jsonl" \
 && ./slsa-verifier verify-artifact "osv-scanner_linux_$arch" --provenance-path multiple.intoto.jsonl \
      --source-uri github.com/google/osv-scanner --source-tag "v${OSV_VERSION}" \
 && install -m 0755 "osv-scanner_linux_$arch" /osv-scanner

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=verify /osv-scanner /osv-scanner
# Offline OSV databases are baked in for the ecosystems in seed/ (PyPI, npm, Go): the sandbox has no
# network at run time. Add a seed lockfile to add an ecosystem; rebuild to refresh.
# (v2 matches offline in roughly constant time; v1.9.2 cost ~0.5s per package and timed out on
# real lockfiles: 250 packages took 140s vs 11s.)
ENV XDG_CACHE_HOME=/osvdb
COPY seed /seed
WORKDIR /seed
# osv-scanner exits non-zero when it finds vulns (the seeds are vulnerable on purpose), so the
# exit code is ignored and the build instead FAILS if the databases did not land.
RUN mkdir /osvdb \
 && (/osv-scanner scan source --offline-vulnerabilities --download-offline-databases --no-resolve -r . || true) \
 && test -s /osvdb/osv-scalibr/PyPI/all.zip && test -s /osvdb/osv-scalibr/npm/all.zip \
 && test -s /osvdb/osv-scalibr/Go/all.zip \
 && chmod -R a+rX /osvdb && du -sh /osvdb
WORKDIR /
USER 10001
ENTRYPOINT ["/osv-scanner"]
