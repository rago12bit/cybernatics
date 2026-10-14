FROM ghcr.io/google/osv-scanner:v2.7.0@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0
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
