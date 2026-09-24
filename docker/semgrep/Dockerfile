FROM semgrep/semgrep:1.90.0
COPY rules /rules
RUN adduser -D -u 10001 scanner
USER 10001
# Sandbox has a read-only rootfs and no network: keep all state in /tmp, never phone home.
ENV HOME=/tmp SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
ENTRYPOINT ["semgrep"]
