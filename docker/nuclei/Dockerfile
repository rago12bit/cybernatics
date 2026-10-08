# Nuclei: the active DAST tier. The template library is baked in at build time, pinned to a release,
# so a campaign downloads nothing: the only traffic it sends is to the verified target, through the
# campaign's egress proxy. (The upstream image ships no templates; it fetched ~86 MB from GitHub on
# every run, outside the proxy.) Rebuild with a newer TEMPLATES to refresh it, as with Grype's
# database. Run with -duc (no update check) and -ni (no interactsh): core/dast/adapters/nuclei.py.
FROM projectdiscovery/nuclei:v3.11.1

ARG TEMPLATES=v10.5.0
RUN apk add --no-cache git \
 && git clone --depth 1 --branch "${TEMPLATES}" https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates \
 && rm -rf /root/nuclei-templates/.git \
 && apk del git \
 && nuclei -duc -tl -silent > /tmp/templates.txt \
 && test "$(wc -l < /tmp/templates.txt)" -gt 5000 \
 && rm /tmp/templates.txt

ENTRYPOINT ["nuclei"]
