FROM ghcr.io/google/osv-scanner:v1.9.2
# Offline OSV databases are baked in for the ecosystems in seed/ (PyPI, npm, Go). osv-scanner caches
# them under $XDG_CACHE_HOME/osv-scanner. Add a seed lockfile to add an ecosystem; rebuild to refresh.
ENV XDG_CACHE_HOME=/osvdb
COPY seed /seed
WORKDIR /seed
# osv-scanner exits non-zero when it finds vulns (the seeds are vulnerable on purpose), so the
# exit code is ignored and the build instead FAILS if the databases did not land.
RUN mkdir /osvdb \
 && (/osv-scanner --experimental-offline-vulnerabilities --experimental-download-offline-databases -r . || true) \
 && test -s /osvdb/osv-scanner/PyPI/all.zip && test -s /osvdb/osv-scanner/npm/all.zip \
 && test -s /osvdb/osv-scanner/Go/all.zip \
 && chmod -R a+rX /osvdb && du -sh /osvdb
WORKDIR /
USER 10001
ENTRYPOINT ["/osv-scanner"]
