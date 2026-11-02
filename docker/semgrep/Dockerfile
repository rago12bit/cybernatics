# Stage 1: fetch community rules at BUILD time from a pinned commit. They are never committed or
# redistributed: Semgrep Rules License v1.0 allows internal business use only (ADR-006).
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS rules
ARG RULES_REV=a84ff9cc2453ca91d581380de4b8b3f272f6f4be
RUN apk add --no-cache git \
 && git clone -q https://github.com/semgrep/semgrep-rules /src \
 && git -C /src checkout -q "$RULES_REV" \
 && mkdir /rules \
 && for d in python javascript typescript go java; do cp -R "/src/$d" "/rules/$d"; done \
 && cp /src/LICENSE /rules/LICENSE

# Stage 2: one file per language instead of hundreds (see merge-rules.py: ~25 s less start-up per scan).
FROM semgrep/semgrep:1.182.1@sha256:451b3d875c00dac7ed5db5293e584a07de11449a409c10b3c2d2652f429630b6 AS merged
COPY --from=rules /rules /rules-src
COPY merge-rules.py /merge-rules.py
RUN python3 /merge-rules.py /rules-src /rules

FROM semgrep/semgrep:1.182.1@sha256:451b3d875c00dac7ed5db5293e584a07de11449a409c10b3c2d2652f429630b6
COPY --from=merged /rules /rules
COPY --from=rules /rules/LICENSE /rules/LICENSE
RUN adduser -D -u 10001 scanner
USER 10001
# Sandbox has a read-only rootfs and no network: keep all state in /tmp, never phone home.
ENV HOME=/tmp SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
ENTRYPOINT ["semgrep"]
